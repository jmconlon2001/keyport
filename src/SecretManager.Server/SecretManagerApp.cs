using System.Net;
using System.Security.Authentication;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using SecretManager.Core.Crypto;
using SecretManager.Server.Api;
using SecretManager.Server.Components;
using SecretManager.Server.Components.Account;
using SecretManager.Server.Configuration;
using SecretManager.Server.Data;
using SecretManager.Server.Edge;
using SecretManager.Server.Services;

namespace SecretManager.Server;

public static class SecretManagerApp
{
    /// <summary>Builds the fully configured application without starting it (used by Program and integration tests).</summary>
    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        // Explicit application name so static-asset manifests resolve even when hosted by a test runner.
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ApplicationName = typeof(SecretManagerApp).Assembly.GetName().Name,
        });
        configure?.Invoke(builder);

        var section = builder.Configuration.GetSection(SecretManagerOptions.Section);
        var smOptions = section.Get<SecretManagerOptions>() ?? new SecretManagerOptions();
        if (Environment.GetEnvironmentVariable("SM_MASTER_KEY_FILE") is { Length: > 0 } keyFile)
            smOptions.MasterKeyFile = keyFile;
        EnvironmentRegistry.Validate(smOptions);
        builder.Services.Configure<SecretManagerOptions>(section);
        builder.Services.PostConfigure<SecretManagerOptions>(o => o.MasterKeyFile = smOptions.MasterKeyFile);

        Directory.CreateDirectory(smOptions.DataPath);

        // Fail fast without the master key: nothing can be decrypted.
        var masterKey = MasterKey.LoadFromFile(smOptions.MasterKeyFile);
        var encryptor = new EnvelopeEncryptor(masterKey);
        builder.Services.AddSingleton(masterKey);
        builder.Services.AddSingleton(encryptor);

        ConfigureKestrel(builder, smOptions);

        // Data
        var dbPath = Path.Combine(smOptions.DataPath, "secretmanager.db");
        // Singleton factory for services/background jobs (one short-lived context per operation);
        // a scoped context for ASP.NET Core Identity's stores.
        builder.Services.AddDbContextFactory<ApplicationDbContext>(o => o.UseSqlite($"Data Source={dbPath};Cache=Shared;Foreign Keys=True"));
        builder.Services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<ApplicationDbContext>>().CreateDbContext());

        // Data protection keys (cookies/antiforgery) persisted on the volume, encrypted with the KEK.
        builder.Services.AddDataProtection()
            .SetApplicationName("SecretManager")
            .PersistKeysToFileSystem(new DirectoryInfo(Path.Combine(smOptions.DataPath, "dp-keys")));
        builder.Services.Configure<KeyManagementOptions>(o => o.XmlEncryptor = new KekXmlEncryptor(encryptor));

        // Core services
        builder.Services.AddSingleton<EnvironmentRegistry>();
        builder.Services.AddSingleton<AuditService>();
        builder.Services.AddSingleton<CertificateManager>();
        builder.Services.AddSingleton<ActivityLogger>();
        builder.Services.AddSingleton<JobStatus>();
        builder.Services.AddSingleton<SecretService>();
        builder.Services.AddSingleton<ApiClientService>();
        builder.Services.AddSingleton<AuditIntegrityMonitor>();
        builder.Services.AddSingleton<ConnectionTester>();
        builder.Services.AddSingleton<UserAdminService>();
        builder.Services.AddScoped<StatusService>();
        builder.Services.AddScoped<AccessService>();
        builder.Services.AddScoped<CircuitClientInfo>();
        builder.Services.AddScoped<CircuitHandler, ClientInfoCircuitHandler>();
        builder.Services.AddHttpContextAccessor();
        builder.Services.AddHostedService<CertificateRenewalService>();
        builder.Services.AddHostedService<ActivityLogWriter>();
        builder.Services.AddHostedService<LogRetentionService>();
        builder.Services.AddHostedService(sp => sp.GetRequiredService<AuditIntegrityMonitor>());

        builder.Services.AddHealthChecks()
            .AddCheck<DatabaseHealthCheck>("database", tags: ["ready"])
            .AddCheck<MasterKeyHealthCheck>("master-key", tags: ["ready"])
            .AddCheck<CertificateHealthCheck>("certificates", tags: ["ready"])
            .AddCheck<DiskSpaceHealthCheck>("disk-space")
            .AddCheck<AuditChainHealthCheck>("audit-chain")
            .AddCheck<BackgroundJobsHealthCheck>("background-jobs");

        // UI + identity
        builder.Services.AddRazorComponents().AddInteractiveServerComponents();
        builder.Services.AddCascadingAuthenticationState();
        builder.Services.AddScoped<IdentityRedirectManager>();
        builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

        builder.Services.AddAuthentication(o =>
            {
                o.DefaultScheme = IdentityConstants.ApplicationScheme;
                o.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            })
            .AddIdentityCookies();

        builder.Services.AddIdentityCore<ApplicationUser>(o =>
            {
                o.SignIn.RequireConfirmedAccount = false;
                o.Stores.SchemaVersion = IdentitySchemaVersions.Version3;
                o.Password.RequiredLength = 12;
                o.Password.RequireNonAlphanumeric = true;
                o.Password.RequiredUniqueChars = 6;
                o.Lockout.MaxFailedAccessAttempts = 5;
                o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
                o.Lockout.AllowedForNewUsers = true;
                o.User.RequireUniqueEmail = false;
            })
            .AddRoles<IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders()
            .AddClaimsPrincipalFactory<AppClaimsPrincipalFactory>();

        builder.Services.Configure<SecurityStampValidatorOptions>(o => o.ValidationInterval = TimeSpan.FromMinutes(1));
        builder.Services.ConfigureApplicationCookie(o =>
        {
            o.Cookie.Name = "__Host-sm-auth";
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            o.Cookie.SameSite = SameSiteMode.Strict;
            o.Cookie.HttpOnly = true;
            o.ExpireTimeSpan = TimeSpan.FromHours(8);
            o.SlidingExpiration = true;
            o.LoginPath = "/Account/Login";
            o.AccessDeniedPath = "/Account/AccessDenied";
            // APIs get status codes, not login-page redirects.
            static bool IsApi(HttpRequest r) => r.Path.StartsWithSegments("/admin/api") || r.Path.StartsWithSegments("/openapi");
            o.Events.OnRedirectToLogin = ctx =>
            {
                if (IsApi(ctx.Request)) ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                else ctx.Response.Redirect(ctx.RedirectUri);
                return Task.CompletedTask;
            };
            o.Events.OnRedirectToAccessDenied = ctx =>
            {
                if (IsApi(ctx.Request)) ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                else ctx.Response.Redirect(ctx.RedirectUri);
                return Task.CompletedTask;
            };
        });
        builder.Services.AddAntiforgery(o =>
        {
            o.Cookie.Name = "__Host-sm-af";
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });

        builder.Services.AddAuthorizationBuilder()
            .AddPolicy(Roles.Admin, p => p.RequireRole(Roles.Admin))
            .AddPolicy(AdminApi.AuditPolicy, p => p.RequireRole(Roles.Admin, Roles.Auditor));

        // Rate limiting: per API client on env ports, per IP on the login form.
        builder.Services.AddRateLimiter(o =>
        {
            o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            o.AddPolicy(SecretsApi.RateLimitPolicy, ctx =>
            {
                var auth = ctx.Request.Headers.Authorization.ToString();
                var key = ApiKeys.TryParsePrefix(auth.Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase).Trim(), out var prefix)
                    ? $"key:{prefix}" : $"ip:{ctx.Connection.RemoteIpAddress}";
                return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
                {
                    PermitLimit = smOptions.Edge.ApiRequestsPerMinute,
                    Window = TimeSpan.FromMinutes(1),
                });
            });
            o.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(ctx =>
                HttpMethods.IsPost(ctx.Request.Method) && ctx.Request.Path.StartsWithSegments("/Account/Login")
                    ? RateLimitPartition.GetFixedWindowLimiter($"login:{ctx.Connection.RemoteIpAddress}",
                        _ => new FixedWindowRateLimiterOptions { PermitLimit = 10, Window = TimeSpan.FromMinutes(1) })
                    : RateLimitPartition.GetNoLimiter("none"));
        });

        builder.Services.AddOpenApi("v1", o => o.AddDocumentTransformer((doc, _, _) =>
        {
            doc.Info.Title = "SecretManager API";
            doc.Info.Description =
                "Secrets API: call /api/v1 on the port of the target environment with 'Authorization: Bearer sm_…'. " +
                "Admin API: /admin/api on the admin port with a signed-in session.";
            return Task.CompletedTask;
        }));

        // Optional upstream routes (built-in reverse proxy). Each route must declare Metadata.Ports.
        builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
        // Routes managed in the UI: stored in the database (on the /data volume), loaded at startup, applied live on save.
        builder.Services.AddSingleton<DbProxyConfigProvider>();
        builder.Services.AddSingleton<Yarp.ReverseProxy.Configuration.IProxyConfigProvider>(sp => sp.GetRequiredService<DbProxyConfigProvider>());
        builder.Services.AddSingleton<ProxyRouteService>();
        builder.Services.AddHttpClient("proxy-test", c => c.Timeout = TimeSpan.FromSeconds(5));

        var app = builder.Build();
        ConfigurePipeline(app);
        return app;
    }

    private static void ConfigureKestrel(WebApplicationBuilder builder, SecretManagerOptions o)
    {
        builder.WebHost.ConfigureKestrel(k =>
        {
            k.AddServerHeader = false;
            k.Limits.MaxRequestBodySize = 1 * 1024 * 1024;
            k.Limits.MaxRequestHeadersTotalSize = 32 * 1024;

            var certs = k.ApplicationServices.GetRequiredService<CertificateManager>();
            void Https(Microsoft.AspNetCore.Server.Kestrel.Core.ListenOptions lo) => lo.UseHttps(h =>
            {
                h.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                h.ServerCertificateSelector = (_, _) => certs.ServerCertificate;
            });

            var defaultAddr = ParseBind(o.Edge.BindAddress);
            if (o.Edge.HttpPort > 0) k.Listen(defaultAddr, o.Edge.HttpPort);
            k.Listen(defaultAddr, o.Edge.AdminPort, Https);
            foreach (var env in o.Environments)
                k.Listen(env.BindAddress is { Length: > 0 } b ? ParseBind(b) : defaultAddr, env.Port, Https);
        });
    }

    private static IPAddress ParseBind(string address) => address switch
    {
        "*" or "::" => IPAddress.IPv6Any,
        "0.0.0.0" or "" => IPAddress.Any,
        "localhost" => IPAddress.Loopback,
        _ => IPAddress.Parse(address),
    };

    private static void ConfigurePipeline(WebApplication app)
    {
        app.UseExceptionHandler("/Error", createScopeForErrors: true);
        app.UseMiddleware<SecurityHeadersMiddleware>();
        app.UseRouting();
        app.UseMiddleware<PortGateMiddleware>();
        app.UseRateLimiter();
        app.UseAuthentication();
        app.UseAuthorization();
        app.UseMiddleware<ActivityLoggingMiddleware>();
        app.UseMiddleware<AccountEnforcementMiddleware>();
        app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
        app.UseAntiforgery();

        // Health: available on every port, unauthenticated, no secrets in the output.
        app.MapHealthChecks("/health/live", new HealthCheckOptions { Predicate = _ => false });
        app.MapHealthChecks("/health/ready", new HealthCheckOptions { Predicate = c => c.Tags.Contains("ready"), ResponseWriter = HealthResponse.WriteAsync });
        app.MapHealthChecks("/health", new HealthCheckOptions
        {
            ResponseWriter = HealthResponse.WriteAsync,
            ResultStatusCodes =
            {
                [HealthStatus.Healthy] = StatusCodes.Status200OK,
                [HealthStatus.Degraded] = StatusCodes.Status200OK,
                [HealthStatus.Unhealthy] = StatusCodes.Status503ServiceUnavailable,
            },
        });

        app.MapGet("/ca.crt", (CertificateManager certs) =>
            Results.Text(certs.TrustAnchorPem, "application/x-pem-file")).ExcludeFromDescription();

        app.MapSecretsApi();
        app.MapAdminApi();
        app.MapOpenApi("/openapi/{documentName}.json").RequireAuthorization();

        app.MapStaticAssets();
        app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
        app.MapAdditionalIdentityEndpoints();
        app.MapReverseProxy();
    }

    /// <summary>Migrates the database, syncs environments, seeds the admin account and initializes the CA. Run before StartAsync.</summary>
    public static async Task InitializeAsync(WebApplication app)
    {
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("SecretManager.Startup");
        var options = app.Services.GetRequiredService<IOptions<SecretManagerOptions>>().Value;

        await using (var scope = app.Services.CreateAsyncScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await db.Database.MigrateAsync();
            await db.Database.ExecuteSqlRawAsync("PRAGMA journal_mode=WAL;");

            var encryptor = scope.ServiceProvider.GetRequiredService<EnvelopeEncryptor>();
            var foreign = await db.SecretVersions.Select(v => v.KeyId).Distinct().Where(k => k != encryptor.KeyId).ToListAsync();
            if (foreign.Count > 0)
                throw new InvalidOperationException(
                    $"Secrets in the database were encrypted with master key(s) {string.Join(", ", foreign)}, but the loaded key is {encryptor.KeyId}. Refusing to start.");

            await app.Services.GetRequiredService<EnvironmentRegistry>().SyncAsync(db);

            // Restore UI-managed reverse-proxy routes persisted in the database.
            var proxy = app.Services.GetRequiredService<DbProxyConfigProvider>();
            proxy.Reload();
            logger.LogInformation("Loaded {Count} reverse-proxy route(s) from the database", proxy.GetConfig().Routes.Count);
            await SeedAsync(scope.ServiceProvider, options, logger);
        }

        app.Services.GetRequiredService<CertificateManager>().Initialize();

        var envs = app.Services.GetRequiredService<EnvironmentRegistry>();
        logger.LogInformation("Admin UI: https://<host>:{AdminPort}  |  Environments: {Envs}", options.Edge.AdminPort,
            string.Join(", ", envs.All.Select(e => $"{e.Name}=:{e.Port}{(e.Protected ? " (protected)" : "")}")));
    }

    private static async Task SeedAsync(IServiceProvider sp, SecretManagerOptions options, ILogger logger)
    {
        var roles = sp.GetRequiredService<RoleManager<IdentityRole>>();
        foreach (var r in Roles.All)
            if (!await roles.RoleExistsAsync(r))
                await roles.CreateAsync(new IdentityRole(r));

        var users = sp.GetRequiredService<UserManager<ApplicationUser>>();
        if (await users.Users.AnyAsync()) return;

        var password = PasswordGenerator.Generate(20);
        var admin = new ApplicationUser
        {
            UserName = options.BootstrapAdminUser,
            DisplayName = "Administrator",
            MustChangePassword = true,
            CreatedUtc = DateTime.UtcNow,
        };
        var result = await users.CreateAsync(admin, password);
        if (!result.Succeeded)
            throw new InvalidOperationException("Could not create bootstrap admin: " + string.Join("; ", result.Errors.Select(e => e.Description)));
        await users.AddToRoleAsync(admin, Roles.Admin);

        // Shown once. The account must change it and enrol MFA at first sign-in.
        logger.LogWarning("""

            ================================================================
              Bootstrap administrator created
                user:     {User}
                password: {Password}
              You must change this password and enrol MFA at first sign-in.
            ================================================================
            """, admin.UserName, password);
        await sp.GetRequiredService<AuditService>().WriteAsync("system", "user.bootstrap", AuditResult.Success, target: admin.UserName);
    }
}

/// <summary>
/// Forces first-sign-in hygiene on the admin port: users flagged MustChangePassword must change it, and every
/// user must enrol an authenticator app or passkey before using the app.
/// </summary>
public sealed class AccountEnforcementMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext ctx, UserManager<ApplicationUser> users)
    {
        var path = ctx.Request.Path;
        if (ctx.User.Identity?.IsAuthenticated != true
            || ctx.Listener().Kind != ListenerKind.Admin
            || !HttpMethods.IsGet(ctx.Request.Method)
            || path.StartsWithSegments("/Account")
            || path.StartsWithSegments("/_blazor")
            || path.StartsWithSegments("/_framework")
            || path.StartsWithSegments("/health")
            || Path.HasExtension(path.Value))
        {
            await next(ctx);
            return;
        }

        var user = await users.GetUserAsync(ctx.User);
        if (user is null)
        {
            await next(ctx);
            return;
        }

        if (user.MustChangePassword)
        {
            ctx.Response.Redirect("/Account/Manage/ChangePassword?required=1");
            return;
        }

        if (!user.TwoFactorEnabled && (await users.GetPasskeysAsync(user)).Count == 0)
        {
            ctx.Response.Redirect("/Account/Manage/EnableAuthenticator?required=1");
            return;
        }

        await next(ctx);
    }
}

/// <summary>Client address for the current Blazor circuit (HttpContext is not available in interactive components).</summary>
public sealed class CircuitClientInfo
{
    public string? ClientIp { get; set; }
}

public sealed class ClientInfoCircuitHandler(IHttpContextAccessor accessor, CircuitClientInfo info) : CircuitHandler
{
    public override Task OnConnectionUpAsync(Circuit circuit, CancellationToken cancellationToken)
    {
        info.ClientIp ??= accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
        return Task.CompletedTask;
    }
}

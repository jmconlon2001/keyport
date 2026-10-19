using System.Net;
using System.Security.Authentication;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Keyport.Core.Crypto;
using Keyport.Core.Secrets.Types;
using Keyport.Server.Api;
using Keyport.Server.Components;
using Keyport.Server.Components.Account;
using Keyport.Server.Configuration;
using Keyport.Server.Data;
using Keyport.Server.Edge;
using Keyport.Server.Services;

namespace Keyport.Server;

public static class KeyportApp
{
    /// <summary>Builds the fully configured application without starting it (used by Program and integration tests).</summary>
    public static WebApplication Build(string[] args, Action<WebApplicationBuilder>? configure = null)
    {
        // Explicit application name so static-asset manifests resolve even when hosted by a test runner.
        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = args,
            ApplicationName = typeof(KeyportApp).Assembly.GetName().Name,
        });
        configure?.Invoke(builder);

        // Deployments configured before the rename (SecretManager:* / SecretManager__*) keep working.
        var legacy = KeyportOptions.LegacyOverrides(builder.Configuration);
        if (legacy.Count > 0) builder.Configuration.AddInMemoryCollection(legacy);

        var section = builder.Configuration.GetSection(KeyportOptions.Section);
        var smOptions = section.Get<KeyportOptions>() ?? new KeyportOptions();
        if ((Environment.GetEnvironmentVariable("KEYPORT_MASTER_KEY_FILE") ?? Environment.GetEnvironmentVariable("SM_MASTER_KEY_FILE")) is { Length: > 0 } keyFile)
            smOptions.MasterKeyFile = keyFile;
        // Container secret mounted under its pre-rename name.
        const string legacySecret = "/run/secrets/sm_master_key";
        if (!File.Exists(smOptions.MasterKeyFile) && smOptions.MasterKeyFile == new KeyportOptions().MasterKeyFile && File.Exists(legacySecret))
            smOptions.MasterKeyFile = legacySecret;
        EnvironmentRegistry.Validate(smOptions);
        builder.Services.Configure<KeyportOptions>(section);
        builder.Services.PostConfigure<KeyportOptions>(o => o.MasterKeyFile = smOptions.MasterKeyFile);

        Directory.CreateDirectory(smOptions.DataPath);

        // Secret types: built-in + configuration + JSON files. Invalid definitions stop startup with a clear message.
        var registry = SecretTypeLoader.Load(smOptions);
        builder.Services.AddSingleton(registry);

        // Fail fast without the master key: nothing can be decrypted.
        var masterKey = MasterKey.LoadFromFile(smOptions.MasterKeyFile);
        var encryptor = new EnvelopeEncryptor(masterKey);
        builder.Services.AddSingleton(masterKey);
        builder.Services.AddSingleton(encryptor);

        ConfigureKestrel(builder, smOptions);

        // Data
        var dbPath = Path.Combine(smOptions.DataPath, "keyport.db");
        AdoptLegacyDatabase(smOptions.DataPath, dbPath);
        // Singleton factory for services/background jobs (one short-lived context per operation);
        // a scoped context for ASP.NET Core Identity's stores.
        builder.Services.AddDbContextFactory<ApplicationDbContext>(o => o.UseSqlite($"Data Source={dbPath};Cache=Shared;Foreign Keys=True"));
        builder.Services.AddScoped(sp => sp.GetRequiredService<IDbContextFactory<ApplicationDbContext>>().CreateDbContext());

        // Data protection keys (cookies/antiforgery) persisted on the volume, encrypted with the KEK.
        builder.Services.AddDataProtection()
            .SetApplicationName("Keyport")
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
        builder.Services.AddSingleton(TimeProvider.System);
        builder.Services.AddSingleton<FailedAuthThrottle>();
        builder.Services.AddSingleton<UserAdminService>();
        builder.Services.AddScoped<StatusService>();
        builder.Services.AddScoped<AccessService>();
        builder.Services.AddScoped<CircuitClientInfo>();
        builder.Services.AddScoped<CircuitHandler, ClientInfoCircuitHandler>();
        builder.Services.AddScoped<CircuitSession>();
        builder.Services.AddScoped<CircuitHandler, CircuitActivityHandler>();
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
            .AddUserStore<KeyportUserStore>()          // authenticator keys and recovery codes encrypted under the master key
            .AddSignInManager()
            .AddDefaultTokenProviders()
            .AddClaimsPrincipalFactory<AppClaimsPrincipalFactory>();

        builder.Services.Configure<SecurityStampValidatorOptions>(o =>
        {
            o.ValidationInterval = TimeSpan.FromMinutes(1);
            // Refreshing the principal must not restart the session clock.
            o.OnRefreshingPrincipal = ctx =>
            {
                if (ctx.CurrentPrincipal?.FindFirst(SessionSecurity.AuthTimeClaim) is { } t && ctx.NewPrincipal?.Identity is ClaimsIdentity id)
                {
                    foreach (var c in id.FindAll(SessionSecurity.AuthTimeClaim).ToList()) id.RemoveClaim(c);
                    id.AddClaim(new Claim(t.Type, t.Value, t.ValueType));
                }
                return Task.CompletedTask;
            };
        });
        builder.Services.ConfigureApplicationCookie(o =>
        {
            o.Cookie.Name = "__Host-kp-auth";
            o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            o.Cookie.SameSite = SameSiteMode.Strict;
            o.Cookie.HttpOnly = true;
            // Idle timeout: the cookie slides while the person is active (open tabs ping /admin/api/ping); absolute limit below.
            o.ExpireTimeSpan = TimeSpan.FromMinutes(smOptions.Auth.IdleTimeoutMinutes);
            o.SlidingExpiration = true;
            o.Events.OnValidatePrincipal = async ctx =>
            {
                if (ctx.Principal is { } p && SessionSecurity.IsExpired(p, smOptions.Auth, DateTimeOffset.UtcNow))
                {
                    ctx.RejectPrincipal();
                    await ctx.HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
                    return;
                }
                await SecurityStampValidator.ValidatePrincipalAsync(ctx);
            };
            o.LoginPath = "/Account/Login";
            o.AccessDeniedPath = "/Account/AccessDenied";
            // APIs get status codes, not login-page redirects.
            static bool IsApi(HttpRequest r) => r.Path.StartsWithSegments("/admin/api") || r.Path.StartsWithSegments("/openapi");
            o.Events.OnRedirectToLogin = ctx =>
            {
                if (IsApi(ctx.Request)) ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                // Signed-in proxy routes on environment ports: sign in on the admin port (no return URL across origins).
                else if (ctx.HttpContext.Listener().Kind != ListenerKind.Admin)
                    ctx.Response.Redirect($"https://{ctx.HttpContext.SafeHost(smOptions.Edge)}:{smOptions.Edge.AdminPort}/Account/Login");
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
        // "Remember this machine" (skip MFA for 14 days) is not offered, and any such cookie issued earlier is ignored.
        builder.Services.Configure<CookieAuthenticationOptions>(IdentityConstants.TwoFactorRememberMeScheme, o =>
            o.Events.OnValidatePrincipal = ctx =>
            {
                ctx.RejectPrincipal();
                return Task.CompletedTask;
            });
        builder.Services.AddAntiforgery(o =>
        {
            o.Cookie.Name = "__Host-kp-af";
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
            doc.Info.Title = "Keyport API";
            doc.Info.Description =
                "Secrets API: call /api/v1 on the port of the target environment with 'Authorization: Bearer sm_…'. " +
                "Admin API: /admin/api on the admin port with a signed-in session.";
            return Task.CompletedTask;
        }));

        // Optional upstream routes (built-in reverse proxy). Each route must declare Metadata.Ports.
        // Every route strips Keyport's cookies and API keys from requests and Keyport cookies from responses.
        builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"))
            .AddTransforms(ProxyHardeningTransforms.Apply)
            .ConfigureHttpClient((_, handler) => handler.ConnectCallback = UpstreamGuard.ConnectCallback(() => smOptions.Proxy));
        // Routes managed in the UI: stored in the database (on the /data volume), loaded at startup, applied live on save.
        builder.Services.AddSingleton<DbProxyConfigProvider>();
        builder.Services.AddSingleton<Yarp.ReverseProxy.Configuration.IProxyConfigProvider>(sp => sp.GetRequiredService<DbProxyConfigProvider>());
        builder.Services.AddSingleton<ProxyRouteService>();
        builder.Services.AddHttpClient("proxy-test", c => c.Timeout = TimeSpan.FromSeconds(5))
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { ConnectCallback = UpstreamGuard.ConnectCallback(() => smOptions.Proxy) });

        var app = builder.Build();
        ConfigurePipeline(app);
        // Published last, so a startup that fails later can't replace the catalogue in use.
        SecretTypeRegistry.Current = registry;
        return app;
    }

    /// <summary>Renames a pre-rename database (secretmanager.db, plus its WAL/SHM files) to keyport.db on first start.</summary>
    private static void AdoptLegacyDatabase(string dataPath, string dbPath)
    {
        var legacy = Path.Combine(dataPath, "secretmanager.db");
        if (File.Exists(dbPath) || !File.Exists(legacy)) return;
        foreach (var suffix in new[] { "", "-wal", "-shm" })
            if (File.Exists(legacy + suffix))
                File.Move(legacy + suffix, dbPath + suffix);
    }

    private static void ConfigureKestrel(WebApplicationBuilder builder, KeyportOptions o)
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
        app.UseMiddleware<AdminOriginGuardMiddleware>();   // after logging, so refusals are visible in the activity log
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
        var logger = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Keyport.Startup");
        var options = app.Services.GetRequiredService<IOptions<KeyportOptions>>().Value;

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

            // Authenticator keys / recovery codes stored by earlier versions in clear are encrypted now.
            var encrypted = await ProtectedTokens.EncryptExistingAsync(db, encryptor);
            if (encrypted > 0) logger.LogInformation("Encrypted {Count} stored authenticator key(s) / recovery code set(s) under the master key", encrypted);

            // Restore UI-managed reverse-proxy routes persisted in the database.
            var proxy = app.Services.GetRequiredService<DbProxyConfigProvider>();
            proxy.Reload();
            logger.LogInformation("Loaded {Count} reverse-proxy route(s) from the database", proxy.GetConfig().Routes.Count);
            if (!options.Proxy.AllowAdminPort)
            {
                var adminPort = options.Edge.AdminPort.ToString();
                var onAdmin = proxy.GetConfig().Routes.Concat(app.Configuration.GetSection("ReverseProxy:Routes").GetChildren()
                        .Select(c => new Yarp.ReverseProxy.Configuration.RouteConfig { RouteId = c.Key, Metadata = new Dictionary<string, string> { ["Ports"] = c["Metadata:Ports"] ?? "" } }))
                    .Where(r => (r.Metadata?.GetValueOrDefault("Ports") ?? "").Split(',', StringSplitOptions.TrimEntries).Contains(adminPort))
                    .Select(r => r.RouteId).ToList();
                if (onAdmin.Count > 0)
                    logger.LogWarning("Proxy route(s) {Routes} list the admin port {Port}; they are NOT served there (Keyport:Proxy:AllowAdminPort is off). Move them to an environment port.",
                        string.Join(", ", onAdmin), adminPort);
            }
            await SeedAsync(scope.ServiceProvider, options, logger);
        }

        app.Services.GetRequiredService<CertificateManager>().Initialize();

        var envs = app.Services.GetRequiredService<EnvironmentRegistry>();
        logger.LogInformation("Admin UI: https://<host>:{AdminPort}  |  Environments: {Envs}", options.Edge.AdminPort,
            string.Join(", ", envs.All.Select(e => $"{e.Name}=:{e.Port}{(e.Protected ? " (protected)" : "")}")));
    }

    private static async Task SeedAsync(IServiceProvider sp, KeyportOptions options, ILogger logger)
    {
        var roles = sp.GetRequiredService<RoleManager<IdentityRole>>();
        foreach (var r in Roles.All)
            if (!await roles.RoleExistsAsync(r))
                await roles.CreateAsync(new IdentityRole(r));

        var users = sp.GetRequiredService<UserManager<ApplicationUser>>();
        if (await users.Users.AnyAsync())
        {
            // The one-time password file is removed once the first admin has changed it.
            if (File.Exists(BootstrapAdmin.PathFor(options))
                && await users.FindByNameAsync(options.BootstrapAdminUser) is not { MustChangePassword: true })
                BootstrapAdmin.Forget(options);
            return;
        }

        var (password, supplied) = BootstrapAdmin.ChoosePassword(options);
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

        // Never logged: logs are often shipped and retained. The account must change it and enrol MFA at first sign-in.
        if (!supplied) BootstrapAdmin.Save(options, admin.UserName!, password);
        logger.LogWarning("""

            ================================================================
              Bootstrap administrator created
                user:     {User}
                password: {Where}
              You must change this password and enrol MFA at first sign-in.
            ================================================================
            """, admin.UserName, supplied
                ? $"the one in {options.BootstrapAdminPasswordFile}"
                : $"run `dotnet Keyport.Server.dll --bootstrap-password` in the container (podman exec keyport …); stored in {BootstrapAdmin.PathFor(options)} until changed");
        await sp.GetRequiredService<AuditService>().WriteAsync("system", "user.bootstrap", AuditResult.Success, target: admin.UserName);
    }
}

/// <summary>
/// Forces first-sign-in hygiene on the admin port. Until a signed-in user has changed a required password and enrolled
/// an authenticator app or passkey, the ONLY things they can reach are the /Account pages and static files:
/// page requests are redirected to the step they still need; everything else (the Blazor hub, admin API, OpenAPI,
/// form posts, downloads) gets 403. <see cref="AccessService"/> applies the same rule, so services refuse too.
/// </summary>
public sealed class AccountEnforcementMiddleware(RequestDelegate next)
{
    private static readonly string[] StaticExtensions = [".css", ".js", ".svg", ".png", ".ico", ".woff", ".woff2", ".map"];

    public async Task InvokeAsync(HttpContext ctx, UserManager<ApplicationUser> users)
    {
        var path = ctx.Request.Path;
        if (ctx.User.Identity?.IsAuthenticated != true
            || ctx.Listener().Kind != ListenerKind.Admin
            || path.StartsWithSegments("/Account")
            || path.StartsWithSegments("/health")
            || IsStaticFile(ctx.Request))
        {
            await next(ctx);
            return;
        }

        var user = await users.GetUserAsync(ctx.User);
        var step = user is null ? null : await PendingStepAsync(users, user);
        if (step is null)
        {
            await next(ctx);
            return;
        }

        var isPage = HttpMethods.IsGet(ctx.Request.Method)
            && !path.StartsWithSegments("/_blazor") && !path.StartsWithSegments("/admin/api") && !path.StartsWithSegments("/openapi");
        if (isPage) ctx.Response.Redirect(step);
        else
        {
            ctx.Items["sm.error"] = "account setup incomplete (password change or MFA enrolment)";
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
        }
    }

    /// <summary>The page the user must complete next, or null when the account is fully set up.</summary>
    public static async Task<string?> PendingStepAsync(UserManager<ApplicationUser> users, ApplicationUser user)
    {
        if (user.MustChangePassword) return "/Account/Manage/ChangePassword?required=1";
        if (!user.TwoFactorEnabled && (await users.GetPasskeysAsync(user)).Count == 0) return "/Account/Manage/EnableAuthenticator?required=1";
        return null;
    }

    private static bool IsStaticFile(HttpRequest r) =>
        (HttpMethods.IsGet(r.Method) || HttpMethods.IsHead(r.Method))
        && (r.Path.StartsWithSegments("/_framework") || r.Path.StartsWithSegments("/_content")
            || StaticExtensions.Contains(Path.GetExtension(r.Path.Value ?? ""), StringComparer.OrdinalIgnoreCase));
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

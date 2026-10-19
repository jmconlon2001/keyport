using Microsoft.Extensions.Diagnostics.HealthChecks;
using Keyport.Core.Secrets;
using Keyport.Core.Secrets.Types;
using Keyport.Server.Edge;
using Keyport.Server.Services;

namespace Keyport.Server.Api;

public sealed record ConnectionComponents(string? Host, int? Port, string? Database, string? ServiceName, string? Sid, string? Username, string? Password);
public sealed record ConnectionResponse(string Name, string Environment, SecretType Type, string ConnectionString, ConnectionComponents Components, int Version);
public sealed record CredentialResponse(string Name, string Environment, SecretType Type, string? Username, string? Password, string? Domain, string? Url, int Version);
/// <summary>
/// Any secret. The first fields keep the original shape; <c>Fields</c> has every field of the type and
/// <c>Outputs</c> everything built from them (connection string, URL, PEM bundle, credentials file, …).
/// </summary>
public sealed record SecretResponse(string Name, string Environment, SecretType Type, string? Value, string? Username, string? Password, string? ConnectionString, int Version,
    IReadOnlyDictionary<string, string?> Fields, IReadOnlyDictionary<string, string> Outputs);
public sealed record SecretListResponse(string Environment, IReadOnlyList<string> Names);
public sealed record ClientStatusResponse(
    string Environment, int Port, string Service, string Version, string Health, DateTime ServerTimeUtc,
    string Client, DateTime KeyIssuedUtc, DateTime? KeyExpiresUtc, IReadOnlyList<string> Grants);
public sealed record ApiError(string Error);

/// <summary>
/// Secrets API, served only on environment ports. Each port is bound to one environment, and an API key
/// is only accepted on its own environment's port.
/// </summary>
public static class SecretsApi
{
    public const string RateLimitPolicy = "api";

    public static void MapSecretsApi(this IEndpointRouteBuilder app)
    {
        var api = app.MapGroup("/api/v1")
            .AddEndpointFilter<ApiKeyFilter>()
            .RequireRateLimiting(RateLimitPolicy)
            .WithTags("Secrets API");

        api.MapGet("/connections/{**name}", GetConnection)
            .Produces<ConnectionResponse>().Produces<ApiError>(404).Produces<ApiError>(401).Produces(429)
            .WithName("GetConnection").WithSummary("Get a database connection string (Oracle or SQL Server) and its components.");
        api.MapGet("/credentials/{**name}", GetCredential)
            .Produces<CredentialResponse>().Produces<ApiError>(404).Produces<ApiError>(401).Produces(429)
            .WithName("GetCredential").WithSummary("Get a username/password (basic auth or service account).");
        api.MapGet("/secrets/{**name}", GetSecret)
            .Produces<SecretResponse>().Produces<ApiError>(404).Produces<ApiError>(401).Produces(429)
            .WithName("GetSecret").WithSummary("Get any secret by name.");
        api.MapGet("/secrets", ListSecrets)
            .WithName("ListSecrets").WithSummary("List secret names this client may read (no values).");
        api.MapGet("/status", ClientStatus)
            .WithName("GetStatus").WithSummary("Status of this environment's endpoint and the calling client.");
    }

    private static async Task<IResult> GetConnection(string name, HttpContext ctx, SecretService secrets, AuditService audit)
    {
        var (resolved, error) = await ResolveAsync(name, ctx, secrets, audit, "api.read-connection", t => t.IsConnection());
        if (error is not null) return error;
        var s = resolved!;
        var m = s.Metadata;
        return Results.Ok(new ConnectionResponse(s.Name, Env(ctx), s.Type, ConnectionStringFactory.Build(s.Type, m, s.Payload),
            new ConnectionComponents(m.Host, m.Port, m.Database, m.ServiceName, m.Sid, s.Payload.Username, s.Payload.Password), s.Version));
    }

    private static async Task<IResult> GetCredential(string name, HttpContext ctx, SecretService secrets, AuditService audit)
    {
        var (resolved, error) = await ResolveAsync(name, ctx, secrets, audit, "api.read-credential", t => t.Definition.HasUsernameAndPassword);
        if (error is not null) return error;
        var s = resolved!;
        return Results.Ok(new CredentialResponse(s.Name, Env(ctx), s.Type, s.Payload.Username, s.Payload.Password, s.Metadata.Domain, s.Metadata.Url, s.Version));
    }

    private static async Task<IResult> GetSecret(string name, HttpContext ctx, SecretService secrets, AuditService audit)
    {
        var (resolved, error) = await ResolveAsync(name, ctx, secrets, audit, "api.read-secret", _ => true);
        if (error is not null) return error;
        var s = resolved!;
        var def = s.Type.Definition;
        var fields = SecretFields.Merge(s.Metadata, s.Payload);
        var outputs = def.IsUnknown ? new Dictionary<string, string>() : SecretTypeRegistry.Current.RenderAll(def, fields);
        return Results.Ok(new SecretResponse(s.Name, Env(ctx), s.Type, s.Payload.Value, s.Payload.Username, s.Payload.Password,
            outputs.GetValueOrDefault(OutputKeys.ConnectionString), s.Version, fields, outputs));
    }

    private static async Task<IResult> ListSecrets(string? prefix, HttpContext ctx, SecretService secrets)
    {
        var client = ctx.ApiClient()!;
        var env = ctx.Listener().Environment!;
        var names = await secrets.ListNamesAsync(env.Id, prefix?.ToLowerInvariant(), ctx.RequestAborted);
        return Results.Ok(new SecretListResponse(env.Name, names.Where(n => ApiClientService.IsGranted(client, n)).ToList()));
    }

    private static async Task<IResult> ClientStatus(HttpContext ctx, HealthCheckService health)
    {
        var client = ctx.ApiClient()!;
        var env = ctx.Listener().Environment!;
        var report = await health.CheckHealthAsync(r => r.Tags.Contains("ready"), ctx.RequestAborted);
        return Results.Ok(new ClientStatusResponse(env.Name, env.Port, "Keyport", StatusService.Version, report.Status.ToString(),
            DateTime.UtcNow, client.Name, DateTime.SpecifyKind(client.KeyCreatedUtc, DateTimeKind.Utc), client.ExpiresUtc, client.Grants.Select(g => g.Pattern).ToList()));
    }

    private static async Task<(ResolvedSecret? Secret, IResult? Error)> ResolveAsync(
        string name, HttpContext ctx, SecretService secrets, AuditService audit, string action, Func<SecretType, bool> typeOk)
    {
        var client = ctx.ApiClient()!;
        var env = ctx.Listener().Environment!;
        name = Uri.UnescapeDataString(name).Trim('/').ToLowerInvariant();
        ctx.SetAuditTarget(name);
        var actor = $"client:{client.Name}";

        // Ungranted and nonexistent look identical to the caller, so names can't be probed.
        if (!SecretNames.IsValid(name) || !ApiClientService.IsGranted(client, name))
        {
            await audit.WriteAsync(actor, action, AuditResult.Denied, env.Name, name, ctx.ClientIp(), "not granted", ctx.RequestAborted);
            return (null, NotFound(ctx, "not granted"));
        }

        var s = await secrets.ResolveAsync(env.Id, name, ctx.RequestAborted);
        if (s is null)
        {
            await audit.WriteAsync(actor, action, AuditResult.Failure, env.Name, name, ctx.ClientIp(), "not found", ctx.RequestAborted);
            return (null, NotFound(ctx, "not found"));
        }
        if (!typeOk(s.Type))
        {
            ctx.Items["sm.error"] = "wrong type";
            await audit.WriteAsync(actor, action, AuditResult.Failure, env.Name, name, ctx.ClientIp(), $"type {s.Type} not served by this endpoint", ctx.RequestAborted);
            return (null, Results.BadRequest(new ApiError($"'{name}' is a {s.Type.DisplayName()}; use /api/v1/secrets/{name}.")));
        }

        await audit.WriteAsync(actor, action, AuditResult.Success, env.Name, name, ctx.ClientIp(), $"v{s.Version}", ctx.RequestAborted);
        return (s, null);
    }

    private static IResult NotFound(HttpContext ctx, string reason)
    {
        ctx.Items["sm.error"] = reason;
        return Results.NotFound(new ApiError("Secret not found."));
    }

    private static string Env(HttpContext ctx) => ctx.Listener().Environment!.Name;
}

/// <summary>Authenticates <c>Authorization: Bearer sm_…</c> (or <c>X-Api-Key</c>) against the port's environment.</summary>
public sealed class ApiKeyFilter(ApiClientService clients, AuditService audit, FailedAuthThrottle throttle) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var ctx = context.HttpContext;
        var env = ctx.Listener().Environment;
        if (env is null) return Results.NotFound();

        // An IP that keeps failing is refused before any key lookup or audit write.
        if (throttle.IsBlocked(ctx.ClientIp()))
        {
            ctx.Items["sm.error"] = "too many failed authentications";
            return Results.Json(new ApiError("Too many failed attempts. Try again in a minute."), statusCode: StatusCodes.Status429TooManyRequests);
        }

        var key = ReadKey(ctx.Request);
        if (key is null)
        {
            throttle.RecordFailure(ctx.ClientIp(), "missing API key");
            return Unauthorized(ctx, "missing API key");
        }

        var result = await clients.AuthenticateAsync(key, env, ctx.Connection.RemoteIpAddress, ctx.RequestAborted);
        if (result.Failure is not null)
        {
            ctx.Items["sm.error"] = result.Failure;
            var actor = result.Client is null ? "client:unknown" : $"client:{result.Client.Name}";
            // Every attempt is in the activity log; the audit trail gets one entry per IP, client and reason per minute.
            var (writeAudit, suppressed) = throttle.RecordFailure(ctx.ClientIp(), $"{actor}|{result.Failure}");
            if (writeAudit)
                await audit.WriteAsync(actor, "api.authenticate", AuditResult.Denied, env.Name, ctx.Request.Path, ctx.ClientIp(),
                    suppressed > 0 ? $"{result.Failure} (+{suppressed} similar in the previous minute)" : result.Failure, ctx.RequestAborted);
            return Unauthorized(ctx, result.Failure);
        }

        ctx.SetApiClient(result.Client!);
        return await next(context);
    }

    private static string? ReadKey(HttpRequest req)
    {
        var auth = req.Headers.Authorization.ToString();
        if (auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return auth[7..].Trim();
        var header = req.Headers["X-Api-Key"].ToString();
        return string.IsNullOrWhiteSpace(header) ? null : header.Trim();
    }

    private static IResult Unauthorized(HttpContext ctx, string reason)
    {
        ctx.Items["sm.error"] ??= reason;
        ctx.Response.Headers.WWWAuthenticate = "Bearer realm=\"Keyport\"";
        // Deliberately generic: the reason is in the audit log, not the response.
        return Results.Json(new ApiError("Invalid or missing API key for this environment."), statusCode: StatusCodes.Status401Unauthorized);
    }
}

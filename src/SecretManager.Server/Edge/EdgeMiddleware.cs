using System.Diagnostics;
using Microsoft.Extensions.Primitives;
using SecretManager.Server.Data;
using SecretManager.Server.Services;
using Yarp.ReverseProxy.Model;

namespace SecretManager.Server.Edge;

public enum ListenerKind { Unknown, Http, Admin, Environment }

/// <summary>Which listener a request arrived on. Derived from the socket's local port, never from headers.</summary>
public sealed record ListenerContext(ListenerKind Kind, EnvironmentInfo? Environment);

public static class HttpContextEdgeExtensions
{
    private const string ClientKey = "sm.apiClient";
    private const string TargetKey = "sm.target";

    public static ListenerContext Listener(this HttpContext ctx) =>
        ctx.Features.Get<ListenerContext>() ?? new ListenerContext(ListenerKind.Unknown, null);

    public static void SetApiClient(this HttpContext ctx, ApiClient client) => ctx.Items[ClientKey] = client;
    public static ApiClient? ApiClient(this HttpContext ctx) => ctx.Items[ClientKey] as ApiClient;
    public static void SetAuditTarget(this HttpContext ctx, string target) => ctx.Items[TargetKey] = target;
    public static string? AuditTarget(this HttpContext ctx) => ctx.Items[TargetKey] as string;
    public static string? ClientIp(this HttpContext ctx) => ctx.Connection.RemoteIpAddress?.ToString();
}

/// <summary>
/// Enforces environment segmentation by port:
///   HTTP port  → /ca.crt and /health only; everything else redirects to the admin UI over HTTPS.
///   Admin port → UI, /admin/api, /openapi; never /api/v1.
///   Env ports  → /api/v1 (bound to that environment) and proxied routes that opt in; nothing else.
/// Must run after UseRouting so proxied routes can be identified.
/// </summary>
public sealed class PortGateMiddleware(RequestDelegate next, EnvironmentRegistry environments, Microsoft.Extensions.Options.IOptions<Configuration.SecretManagerOptions> options)
{
    /// <summary>Only redirect to names the certificate covers; never echo an arbitrary Host header (open redirect).</summary>
    private string RedirectHost(HttpContext ctx)
    {
        var edge = options.Value.Edge;
        var host = ctx.Request.Host.Host;
        var known = edge.HostNames.Concat(edge.IpAddresses);
        return known.Contains(host, StringComparer.OrdinalIgnoreCase) ? host : edge.HostNames.FirstOrDefault() ?? "localhost";
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        var port = ctx.Connection.LocalPort;
        var listener = port == environments.AdminPort ? new ListenerContext(ListenerKind.Admin, null)
            : port == environments.HttpPort && environments.HttpPort > 0 ? new ListenerContext(ListenerKind.Http, null)
            : environments.ByPort(port) is { } env ? new ListenerContext(ListenerKind.Environment, env)
            : new ListenerContext(ListenerKind.Unknown, null);
        ctx.Features.Set(listener);

        var path = ctx.Request.Path;
        if (path.StartsWithSegments("/health"))
        {
            await next(ctx);
            return;
        }

        var proxyRoute = ctx.GetEndpoint()?.Metadata.GetMetadata<RouteModel>();
        if (proxyRoute is not null)
        {
            // Proxied routes must list the ports they may be served on in route metadata: { "Ports": "9443,9444" }.
            var allowed = proxyRoute.Config.Metadata?.GetValueOrDefault("Ports")?.Split(',', StringSplitOptions.TrimEntries) ?? [];
            if (allowed.Contains(port.ToString())) await next(ctx);
            else NotFound(ctx);
            return;
        }

        switch (listener.Kind)
        {
            case ListenerKind.Http:
                if (path.Equals("/ca.crt", StringComparison.OrdinalIgnoreCase))
                {
                    await next(ctx);
                    return;
                }
                var host = RedirectHost(ctx);
                ctx.Response.Redirect($"https://{host}:{environments.AdminPort}{ctx.Request.PathBase}{path}{ctx.Request.QueryString}", permanent: false);
                return;

            case ListenerKind.Admin when !path.StartsWithSegments("/api"):
            case ListenerKind.Environment when path.StartsWithSegments("/api/v1"):
                await next(ctx);
                return;

            default:
                NotFound(ctx);
                return;
        }
    }

    private static void NotFound(HttpContext ctx)
    {
        ctx.Response.StatusCode = StatusCodes.Status404NotFound;
        ctx.Response.Headers.CacheControl = "no-store";
    }
}

/// <summary>Hardening headers. CSP is strict: no inline scripts, no third-party origins.</summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    private const string Csp =
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; " +
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'";

    public Task InvokeAsync(HttpContext ctx)
    {
        ctx.Response.OnStarting(() =>
        {
            var h = ctx.Response.Headers;
            h.XContentTypeOptions = "nosniff";
            h.XFrameOptions = "DENY";
            h["Referrer-Policy"] = "no-referrer";
            h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()";
            h["Cross-Origin-Opener-Policy"] = "same-origin";
            h["Cross-Origin-Resource-Policy"] = "same-origin";
            if (ctx.Request.IsHttps)
                h.StrictTransportSecurity = "max-age=31536000";

            var listener = ctx.Listener();
            if (listener.Kind == ListenerKind.Admin)
                h.ContentSecurityPolicy = Csp;
            if (listener.Kind == ListenerKind.Environment || ctx.Request.Path.StartsWithSegments("/admin/api"))
            {
                h.CacheControl = "no-store";
                h.Pragma = "no-cache";
            }
            h.Remove("Server");
            h.Remove("X-Powered-By");
            return Task.CompletedTask;
        });
        return next(ctx);
    }
}

/// <summary>Writes every API request and every UI request (pages, downloads, form posts) to the activity log.</summary>
public sealed class ActivityLoggingMiddleware(RequestDelegate next, ActivityLogger activity)
{
    private static readonly string[] SkipPrefixes = ["/_framework", "/_blazor", "/_content", "/lib", "/css", "/js", "/img", "/health"];

    public async Task InvokeAsync(HttpContext ctx)
    {
        var listener = ctx.Listener();
        var path = ctx.Request.Path.Value ?? "/";
        var isApi = listener.Kind == ListenerKind.Environment;
        var isUi = listener.Kind == ListenerKind.Admin && !IsAsset(path);

        if (!isApi && !isUi)
        {
            await next(ctx);
            return;
        }

        var sw = Stopwatch.StartNew();
        string? error = null;
        try
        {
            await next(ctx);
        }
        catch (Exception ex)
        {
            error = ex.GetType().Name;
            throw;
        }
        finally
        {
            sw.Stop();
            var status = error is null ? ctx.Response.StatusCode : 500;
            activity.Log(new ActivityLog
            {
                Source = isApi ? LogSource.Api : LogSource.Ui,
                Environment = listener.Environment?.Name,
                Actor = isApi
                    ? ctx.ApiClient()?.Name ?? ClientHint(ctx)
                    : ctx.User.Identity?.IsAuthenticated == true ? ctx.User.Identity.Name : "anonymous",
                Method = ctx.Request.Method,
                Path = path,
                Action = isApi ? "api.request" : "ui.request",
                Target = ctx.AuditTarget(),
                StatusCode = status,
                DurationMs = Math.Round(sw.Elapsed.TotalMilliseconds, 2),
                ClientIp = ctx.ClientIp(),
                UserAgent = ctx.Request.Headers.UserAgent.ToString(),
                Error = error ?? (status >= 400 ? ctx.Items["sm.error"] as string : null),
            });
        }
    }

    private static bool IsAsset(string path) =>
        SkipPrefixes.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase)) ||
        (Path.HasExtension(path) && !path.EndsWith(".csv", StringComparison.OrdinalIgnoreCase) && !path.EndsWith(".crt", StringComparison.OrdinalIgnoreCase));

    /// <summary>For unauthenticated API calls, record the public key prefix (if any) so failed attempts are attributable.</summary>
    private static string ClientHint(HttpContext ctx)
    {
        var auth = ctx.Request.Headers.Authorization;
        if (StringValues.IsNullOrEmpty(auth)) return "anonymous";
        var parts = auth.ToString().Split(' ', 2);
        var key = parts.Length == 2 ? parts[1] : "";
        return Core.Crypto.ApiKeys.TryParsePrefix(key, out var prefix) ? $"key:{prefix}" : "invalid-key";
    }
}

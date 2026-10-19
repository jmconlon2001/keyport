using System.Diagnostics;
using Microsoft.Extensions.Primitives;
using Keyport.Server.Data;
using Keyport.Server.Services;
using Yarp.ReverseProxy.Model;

namespace Keyport.Server.Edge;

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

    /// <summary>The request's host if the certificate covers it, else the first configured name. Never echoes an arbitrary Host header (open redirect).</summary>
    public static string SafeHost(this HttpContext ctx, Configuration.EdgeOptions edge)
    {
        var host = ctx.Request.Host.Host;
        return edge.HostNames.Concat(edge.IpAddresses).Contains(host, StringComparer.OrdinalIgnoreCase) ? host : edge.HostNames.FirstOrDefault() ?? "localhost";
    }
}

/// <summary>
/// Enforces environment segmentation by port:
///   HTTP port  → /ca.crt and /health only; everything else redirects to the admin UI over HTTPS.
///   Admin port → UI, /admin/api, /openapi; never /api/v1.
///   Env ports  → /api/v1 (bound to that environment) and proxied routes that opt in; nothing else.
/// Must run after UseRouting so proxied routes can be identified.
/// </summary>
public sealed class PortGateMiddleware(RequestDelegate next, EnvironmentRegistry environments, Microsoft.Extensions.Options.IOptions<Configuration.KeyportOptions> options)
{
    private string RedirectHost(HttpContext ctx) => ctx.SafeHost(options.Value.Edge);

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
            // Never on the admin port unless explicitly allowed: the upstream would share the admin UI's origin.
            var adminBlocked = listener.Kind == ListenerKind.Admin && !options.Value.Proxy.AllowAdminPort;
            if (allowed.Contains(port.ToString()) && !adminBlocked) await next(ctx);
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

/// <summary>
/// Cross-site request guard for the admin port. Pages on other ports of the same host are "same-site", so browsers
/// attach the admin cookie to their requests (including WebSockets, which CORS does not cover). State-changing
/// requests and Blazor hub connections must come from the admin origin itself:
///   - browsers send <c>Sec-Fetch-Site</c> (can't be set by page script): only <c>same-origin</c> (or <c>none</c>,
///     a typed/bookmarked request) is accepted;
///   - otherwise <c>Origin</c>, when present, must be the admin origin (<c>Origin: null</c>, e.g. from a sandboxed
///     frame, is refused);
///   - requests with neither (non-browser clients) are not affected; they carry no ambient cookies.
/// </summary>
public sealed class AdminOriginGuardMiddleware(RequestDelegate next)
{
    public Task InvokeAsync(HttpContext ctx)
    {
        if (ctx.Listener().Kind == ListenerKind.Admin
            && (ctx.Request.Path.StartsWithSegments("/_blazor") || !(HttpMethods.IsGet(ctx.Request.Method) || HttpMethods.IsHead(ctx.Request.Method) || HttpMethods.IsOptions(ctx.Request.Method)))
            && IsCrossOrigin(ctx.Request))
        {
            ctx.Items["sm.error"] = "cross-origin request refused";
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        }
        return next(ctx);
    }

    private static bool IsCrossOrigin(HttpRequest r)
    {
        var site = r.Headers["Sec-Fetch-Site"].ToString();
        if (site.Length > 0) return site is not ("same-origin" or "none");
        return r.Headers.Origin is { Count: > 0 } origin && !IsSameOrigin(origin.ToString(), r);
    }

    public static bool IsSameOrigin(string origin, HttpRequest request) =>
        Uri.TryCreate(origin, UriKind.Absolute, out var o)
        && o.Scheme == Uri.UriSchemeHttps
        && string.Equals(o.Host, request.Host.Host, StringComparison.OrdinalIgnoreCase)
        && o.Port == (request.Host.Port ?? 443);
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
            // The admin origin always gets the strict CSP, including any proxied route allowed there.
            // ("Relax CSP" on a route only matters on environment ports, where Keyport sets no CSP of its own.)
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

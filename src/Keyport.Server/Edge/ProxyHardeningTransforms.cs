using Microsoft.Net.Http.Headers;
using Yarp.ReverseProxy.Transforms;
using Yarp.ReverseProxy.Transforms.Builder;

namespace Keyport.Server.Edge;

/// <summary>
/// Applied to every proxied route (configuration and UI-managed). Keyport's own credentials never reach an upstream,
/// and an upstream can never set Keyport's cookies:
///   request  → Keyport cookies removed from <c>Cookie</c>; Keyport API keys removed (<c>Authorization: Bearer kp_…</c>, <c>X-Api-Key</c>)
///   response → <c>Set-Cookie</c> for Keyport / ASP.NET Core / Identity cookie names dropped
/// Browsers send cookies to every port of a host, so without this a route on any port would receive the admin session.
/// </summary>
public static class ProxyHardeningTransforms
{
    private static readonly string[] ProtectedCookiePrefixes = ["__Host-kp", ".AspNetCore.", "Identity."];

    public static bool IsProtectedCookie(string name) =>
        ProtectedCookiePrefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    public static bool IsKeyportApiKey(string? authorization)
    {
        if (string.IsNullOrEmpty(authorization)) return false;
        var parts = authorization.Split(' ', 2, StringSplitOptions.TrimEntries);
        var token = parts.Length == 2 && parts[0].Equals("Bearer", StringComparison.OrdinalIgnoreCase) ? parts[1] : authorization.Trim();
        return Core.Crypto.ApiKeys.TryParsePrefix(token, out _);
    }

    public static void Apply(TransformBuilderContext context)
    {
        context.AddRequestTransform(t =>
        {
            var headers = t.ProxyRequest.Headers;

            if (headers.Contains(HeaderNames.Cookie))
            {
                var kept = t.HttpContext.Request.Cookies
                    .Where(c => !IsProtectedCookie(c.Key))
                    .Select(c => $"{c.Key}={c.Value}")
                    .ToList();
                headers.Remove(HeaderNames.Cookie);
                if (kept.Count > 0) headers.TryAddWithoutValidation(HeaderNames.Cookie, string.Join("; ", kept));
            }

            if (headers.TryGetValues(HeaderNames.Authorization, out var auth) && auth.Any(IsKeyportApiKey))
                headers.Remove(HeaderNames.Authorization);
            headers.Remove("X-Api-Key");
            return ValueTask.CompletedTask;
        });

        context.AddResponseTransform(t =>
        {
            var response = t.HttpContext.Response.Headers;
            var setCookies = response.SetCookie;
            if (setCookies.Count == 0) return ValueTask.CompletedTask;

            var kept = setCookies
                .Where(v => v is not null && !IsProtectedCookie(v.Split('=', 2)[0].Trim()))
                .ToArray();
            if (kept.Length != setCookies.Count) response.SetCookie = kept;
            return ValueTask.CompletedTask;
        });
    }
}

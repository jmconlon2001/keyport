using System.Globalization;
using System.Security.Claims;
using Microsoft.AspNetCore.Components.Server.Circuits;
using Keyport.Server.Configuration;

namespace Keyport.Server.Services;

/// <summary>
/// Session limits (Keyport:Auth):
///   idle      — no activity for <see cref="AuthOptions.IdleTimeoutMinutes"/> signs you out (cookie and open tabs);
///   absolute  — every session ends <see cref="AuthOptions.AbsoluteSessionHours"/> after the password/passkey sign-in;
///   step-up   — showing values in a protected environment needs a sign-in, or an authenticator code, from the last
///               <see cref="AuthOptions.StepUpMinutes"/> minutes.
/// The sign-in time travels in the <see cref="AuthTimeClaim"/> claim (kept when Identity refreshes the principal).
/// </summary>
public static class SessionSecurity
{
    public const string AuthTimeClaim = "kp:auth_time";

    public static Claim NewAuthTimeClaim(DateTimeOffset now) =>
        new(AuthTimeClaim, now.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture), ClaimValueTypes.Integer64);

    public static DateTimeOffset? AuthTime(ClaimsPrincipal user) =>
        long.TryParse(user.FindFirstValue(AuthTimeClaim), NumberStyles.Integer, CultureInfo.InvariantCulture, out var s)
            ? DateTimeOffset.FromUnixTimeSeconds(s) : null;

    /// <summary>True when the session is past its absolute lifetime (or predates sign-in times being recorded).</summary>
    public static bool IsExpired(ClaimsPrincipal user, AuthOptions o, DateTimeOffset now) =>
        AuthTime(user) is not { } t || now - t > TimeSpan.FromHours(o.AbsoluteSessionHours);
}

/// <summary>Per-circuit (per open tab) record of the last user activity and the last step-up.</summary>
public sealed class CircuitSession(TimeProvider time)
{
    public DateTimeOffset LastActivity { get; private set; } = time.GetUtcNow();
    public DateTimeOffset? LastStepUp { get; private set; }

    public void Touch() => LastActivity = time.GetUtcNow();
    public void SteppedUp() => LastStepUp = time.GetUtcNow();

    public bool NeedsStepUp(ClaimsPrincipal user, AuthOptions o)
    {
        var now = time.GetUtcNow();
        var window = TimeSpan.FromMinutes(o.StepUpMinutes);
        var signedIn = SessionSecurity.AuthTime(user);
        return !(signedIn is { } s && now - s <= window) && !(LastStepUp is { } u && now - u <= window);
    }
}

/// <summary>Every event, JS call or render request from the browser counts as activity for the idle timeout.</summary>
public sealed class CircuitActivityHandler(CircuitSession session) : CircuitHandler
{
    public override Func<CircuitInboundActivityContext, Task> CreateInboundActivityHandler(Func<CircuitInboundActivityContext, Task> next) =>
        context =>
        {
            session.Touch();
            return next(context);
        };
}

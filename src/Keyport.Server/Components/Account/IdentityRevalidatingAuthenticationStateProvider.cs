using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Server;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Keyport.Server.Data;

namespace Keyport.Server.Components.Account;

// Server-side AuthenticationStateProvider for interactive circuits (open tabs). Every minute it signs the tab out if
// the security stamp changed (password, roles, MFA or account disabled), the tab has been idle too long, or the
// session is past its absolute lifetime.
internal sealed class IdentityRevalidatingAuthenticationStateProvider(
        ILoggerFactory loggerFactory,
        IServiceScopeFactory scopeFactory,
        IOptions<IdentityOptions> options,
        IOptions<Keyport.Server.Configuration.KeyportOptions> keyport,
        Keyport.Server.Services.CircuitSession session,
        TimeProvider time)
    : RevalidatingServerAuthenticationStateProvider(loggerFactory)
{
    protected override TimeSpan RevalidationInterval => TimeSpan.FromMinutes(1);

    protected override async Task<bool> ValidateAuthenticationStateAsync(
        AuthenticationState authenticationState, CancellationToken cancellationToken)
    {
        var auth = keyport.Value.Auth;
        var now = time.GetUtcNow();
        if (now - session.LastActivity > TimeSpan.FromMinutes(auth.IdleTimeoutMinutes)) return false;
        if (Keyport.Server.Services.SessionSecurity.IsExpired(authenticationState.User, auth, now)) return false;

        // Get the user manager from a new scope to ensure it fetches fresh data
        await using var scope = scopeFactory.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        return await ValidateSecurityStampAsync(userManager, authenticationState.User);
    }

    private async Task<bool> ValidateSecurityStampAsync(UserManager<ApplicationUser> userManager, ClaimsPrincipal principal)
    {
        var user = await userManager.GetUserAsync(principal);
        if (user is null)
        {
            return false;
        }
        else if (!userManager.SupportsUserSecurityStamp)
        {
            return true;
        }
        else
        {
            var principalStamp = principal.FindFirstValue(options.Value.ClaimsIdentity.SecurityStampClaimType);
            var userStamp = await userManager.GetSecurityStampAsync(user);
            return principalStamp == userStamp;
        }
    }
}

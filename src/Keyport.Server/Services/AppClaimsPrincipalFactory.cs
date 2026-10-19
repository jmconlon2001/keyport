using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Keyport.Server.Data;

namespace Keyport.Server.Services;

/// <summary>Adds the user's display name (so the UI can greet people by name) and the sign-in time to the session.</summary>
public sealed class AppClaimsPrincipalFactory(
    UserManager<ApplicationUser> users, RoleManager<IdentityRole> roles, IOptions<IdentityOptions> options, TimeProvider time)
    : UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>(users, roles, options)
{
    public const string DisplayNameClaim = "sm:display_name";

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var id = await base.GenerateClaimsAsync(user);
        if (!string.IsNullOrWhiteSpace(user.DisplayName))
            id.AddClaim(new Claim(DisplayNameClaim, user.DisplayName));
        // Sign-in time, for the absolute session limit and step-up. Carried over when Identity refreshes the principal.
        id.AddClaim(SessionSecurity.NewAuthTimeClaim(time.GetUtcNow()));
        return id;
    }
}

public static class PrincipalExtensions
{
    public static string DisplayName(this ClaimsPrincipal user) =>
        user.FindFirst(AppClaimsPrincipalFactory.DisplayNameClaim)?.Value ?? user.Identity?.Name ?? "";

    public static string FirstName(this ClaimsPrincipal user) => user.DisplayName().Split(' ', '.')[0] is var f && f.Length > 0
        ? char.ToUpperInvariant(f[0]) + f[1..] : "";
}

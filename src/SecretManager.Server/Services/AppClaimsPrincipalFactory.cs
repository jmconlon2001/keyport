using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using SecretManager.Server.Data;

namespace SecretManager.Server.Services;

/// <summary>Adds the user's display name to the sign-in session so the UI can greet people by name.</summary>
public sealed class AppClaimsPrincipalFactory(
    UserManager<ApplicationUser> users, RoleManager<IdentityRole> roles, IOptions<IdentityOptions> options)
    : UserClaimsPrincipalFactory<ApplicationUser, IdentityRole>(users, roles, options)
{
    public const string DisplayNameClaim = "sm:display_name";

    protected override async Task<ClaimsIdentity> GenerateClaimsAsync(ApplicationUser user)
    {
        var id = await base.GenerateClaimsAsync(user);
        if (!string.IsNullOrWhiteSpace(user.DisplayName))
            id.AddClaim(new Claim(DisplayNameClaim, user.DisplayName));
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

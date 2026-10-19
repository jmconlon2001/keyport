using System.Security.Claims;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.EntityFrameworkCore;
using Keyport.Server.Data;

namespace Keyport.Server.Services;

/// <summary>What the signed-in user may do. Admins can do everything; others get per-environment Viewer/Editor grants.</summary>
public sealed record UserAccess(string UserId, string UserName, bool IsAdmin, bool IsAuditor, IReadOnlyDictionary<int, EnvironmentRole> Roles)
{
    public static readonly UserAccess Anonymous = new("", "", false, false, new Dictionary<int, EnvironmentRole>());

    public bool CanView(int environmentId) => IsAdmin || Roles.ContainsKey(environmentId);
    public bool CanEdit(int environmentId) => IsAdmin || Roles.GetValueOrDefault(environmentId) == EnvironmentRole.Editor;
    public bool CanReadAudit => IsAdmin || IsAuditor;
}

/// <summary>Resolves <see cref="UserAccess"/> for the current Blazor circuit (cached per circuit/request scope).</summary>
public sealed class AccessService
{
    private readonly AuthenticationStateProvider authState;
    private readonly IDbContextFactory<ApplicationDbContext> dbFactory;
    private UserAccess? _cached;

    public AccessService(AuthenticationStateProvider authState, IDbContextFactory<ApplicationDbContext> dbFactory)
    {
        this.authState = authState;
        this.dbFactory = dbFactory;
        // Signed out, timed out or roles changed (the revalidator checks every minute): look the user up again.
        authState.AuthenticationStateChanged += _ => _cached = null;
    }

    public async Task<UserAccess> GetAsync()
    {
        if (_cached is not null) return _cached;
        var state = await authState.GetAuthenticationStateAsync();
        return _cached = await ForPrincipalAsync(state.User);
    }

    public async Task<UserAccess> ForPrincipalAsync(ClaimsPrincipal user)
    {
        var id = user.FindFirstValue(ClaimTypes.NameIdentifier);
        if (user.Identity?.IsAuthenticated != true || id is null) return UserAccess.Anonymous;

        await using var db = await dbFactory.CreateDbContextAsync();

        // Same rule as AccountEnforcementMiddleware: no access until the password is changed and MFA is enrolled.
        var account = await db.Users.AsNoTracking().Where(u => u.Id == id)
            .Select(u => new { u.MustChangePassword, u.TwoFactorEnabled }).FirstOrDefaultAsync();
        if (account is null || account.MustChangePassword) return UserAccess.Anonymous;
        if (!account.TwoFactorEnabled && !await db.Set<Microsoft.AspNetCore.Identity.IdentityUserPasskey<string>>().AnyAsync(p => p.UserId == id))
            return UserAccess.Anonymous;

        var roles = await db.UserEnvironmentRoles.AsNoTracking().Where(r => r.UserId == id).ToDictionaryAsync(r => r.EnvironmentId, r => r.Role);
        return new UserAccess(id, user.Identity.Name ?? id, user.IsInRole(Roles.Admin), user.IsInRole(Roles.Auditor), roles);
    }
}

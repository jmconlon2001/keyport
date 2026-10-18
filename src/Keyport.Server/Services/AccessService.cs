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
public sealed class AccessService(AuthenticationStateProvider authState, IDbContextFactory<ApplicationDbContext> dbFactory)
{
    private UserAccess? _cached;

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
        var roles = await db.UserEnvironmentRoles.AsNoTracking().Where(r => r.UserId == id).ToDictionaryAsync(r => r.EnvironmentId, r => r.Role);
        return new UserAccess(id, user.Identity.Name ?? id, user.IsInRole(Roles.Admin), user.IsInRole(Roles.Auditor), roles);
    }
}

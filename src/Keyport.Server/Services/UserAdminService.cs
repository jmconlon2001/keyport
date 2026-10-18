using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Keyport.Core.Crypto;
using Keyport.Server.Data;

namespace Keyport.Server.Services;

public sealed record UserRow(
    string Id, string UserName, string? DisplayName, bool IsAdmin, bool IsAuditor, bool MfaEnabled, int Passkeys,
    bool Disabled, bool LockedOut, bool MustChangePassword, DateTime CreatedUtc, IReadOnlyDictionary<int, EnvironmentRole> EnvRoles)
{
    public bool IsSelf(UserAccess a) => a.UserId == Id;
}

public sealed class SaveUserRequest
{
    public string UserName { get; set; } = "";
    public string? DisplayName { get; set; }
    public bool IsAdmin { get; set; }
    public bool IsAuditor { get; set; }
    public Dictionary<int, EnvironmentRole?> EnvRoles { get; set; } = [];
}

/// <summary>
/// User administration (Admin only). Each call uses its own DI scope so Identity's DbContext is never
/// shared across a long-lived Blazor circuit. Every change is audited.
/// </summary>
public sealed class UserAdminService(IServiceScopeFactory scopes, AuditService audit, EnvironmentRegistry environments)
{
    public async Task<List<UserRow>> ListAsync(UserAccess actor)
    {
        RequireAdmin(actor);
        await using var scope = scopes.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        var users = await db.Users.AsNoTracking().OrderBy(u => u.UserName).ToListAsync();
        var roleMap = await (from ur in db.UserRoles join r in db.Roles on ur.RoleId equals r.Id select new { ur.UserId, r.Name }).ToListAsync();
        var envRoles = await db.UserEnvironmentRoles.AsNoTracking().ToListAsync();
        var passkeys = await db.UserPasskeys.GroupBy(p => p.UserId).Select(g => new { g.Key, C = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.C);
        var now = DateTimeOffset.UtcNow;

        return users.Select(u => new UserRow(
            u.Id, u.UserName!, u.DisplayName,
            roleMap.Any(r => r.UserId == u.Id && r.Name == Roles.Admin),
            roleMap.Any(r => r.UserId == u.Id && r.Name == Roles.Auditor),
            u.TwoFactorEnabled, passkeys.GetValueOrDefault(u.Id),
            u.LockoutEnd == DateTimeOffset.MaxValue,
            u.LockoutEnd is { } le && le > now && le != DateTimeOffset.MaxValue,
            u.MustChangePassword, u.CreatedUtc,
            envRoles.Where(r => r.UserId == u.Id).ToDictionary(r => r.EnvironmentId, r => r.Role))).ToList();
    }

    /// <summary>Creates a user with a random temporary password (returned once). The user must change it and enrol MFA.</summary>
    public async Task<string> CreateAsync(UserAccess actor, SaveUserRequest req, string? ip)
    {
        RequireAdmin(actor);
        var name = req.UserName.Trim().ToLowerInvariant();
        if (name.Length is < 2 or > 64 || !name.All(c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '@'))
            throw new ValidationException("Username must be 2-64 characters: letters, digits, '.', '_', '-' or '@'.");

        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        if (await users.FindByNameAsync(name) is not null)
            throw new ValidationException($"User '{name}' already exists.");

        var password = PasswordGenerator.Generate(20);
        var user = new ApplicationUser { UserName = name, DisplayName = req.DisplayName?.Trim(), MustChangePassword = true, CreatedUtc = DateTime.UtcNow };
        Check(await users.CreateAsync(user, password));
        await ApplyRolesAsync(scope.ServiceProvider, user, req);
        await audit.WriteAsync(actor.UserName, "user.create", AuditResult.Success, target: name, clientIp: ip, details: Describe(req));
        return password;
    }

    public async Task UpdateAsync(UserAccess actor, string userId, SaveUserRequest req, string? ip)
    {
        RequireAdmin(actor);
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByIdAsync(userId) ?? throw new KeyNotFoundException();

        if (user.Id == actor.UserId && !req.IsAdmin)
            throw new ValidationException("You cannot remove your own Admin role.");
        if (!req.IsAdmin && await users.IsInRoleAsync(user, Roles.Admin) && (await users.GetUsersInRoleAsync(Roles.Admin)).Count <= 1)
            throw new ValidationException("At least one administrator is required.");

        user.DisplayName = req.DisplayName?.Trim();
        Check(await users.UpdateAsync(user));
        await ApplyRolesAsync(scope.ServiceProvider, user, req);
        // Invalidate existing sessions so role changes apply immediately.
        await users.UpdateSecurityStampAsync(user);
        await audit.WriteAsync(actor.UserName, "user.update-access", AuditResult.Success, target: user.UserName, clientIp: ip, details: Describe(req));
    }

    public async Task<string> ResetPasswordAsync(UserAccess actor, string userId, string? ip)
    {
        RequireAdmin(actor);
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByIdAsync(userId) ?? throw new KeyNotFoundException();
        var password = PasswordGenerator.Generate(20);
        var token = await users.GeneratePasswordResetTokenAsync(user);
        Check(await users.ResetPasswordAsync(user, token, password));
        user.MustChangePassword = true;
        Check(await users.UpdateAsync(user));
        await audit.WriteAsync(actor.UserName, "user.reset-password", AuditResult.Success, target: user.UserName, clientIp: ip);
        return password;
    }

    public async Task ResetMfaAsync(UserAccess actor, string userId, string? ip)
    {
        RequireAdmin(actor);
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByIdAsync(userId) ?? throw new KeyNotFoundException();
        await users.SetTwoFactorEnabledAsync(user, false);
        await users.ResetAuthenticatorKeyAsync(user);
        foreach (var pk in await users.GetPasskeysAsync(user))
            await users.RemovePasskeyAsync(user, pk.CredentialId);
        await users.UpdateSecurityStampAsync(user);
        await audit.WriteAsync(actor.UserName, "user.reset-mfa", AuditResult.Success, target: user.UserName, clientIp: ip);
    }

    public async Task SetDisabledAsync(UserAccess actor, string userId, bool disabled, string? ip)
    {
        RequireAdmin(actor);
        if (userId == actor.UserId) throw new ValidationException("You cannot disable your own account.");
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByIdAsync(userId) ?? throw new KeyNotFoundException();
        await users.SetLockoutEnabledAsync(user, true);
        Check(await users.SetLockoutEndDateAsync(user, disabled ? DateTimeOffset.MaxValue : null));
        await users.UpdateSecurityStampAsync(user);
        await audit.WriteAsync(actor.UserName, disabled ? "user.disable" : "user.enable", AuditResult.Success, target: user.UserName, clientIp: ip);
    }

    public async Task UnlockAsync(UserAccess actor, string userId, string? ip)
    {
        RequireAdmin(actor);
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByIdAsync(userId) ?? throw new KeyNotFoundException();
        Check(await users.SetLockoutEndDateAsync(user, null));
        await users.ResetAccessFailedCountAsync(user);
        await audit.WriteAsync(actor.UserName, "user.unlock", AuditResult.Success, target: user.UserName, clientIp: ip);
    }

    public async Task DeleteAsync(UserAccess actor, string userId, string? ip)
    {
        RequireAdmin(actor);
        if (userId == actor.UserId) throw new ValidationException("You cannot delete your own account.");
        await using var scope = scopes.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByIdAsync(userId) ?? throw new KeyNotFoundException();
        if (await users.IsInRoleAsync(user, Roles.Admin) && (await users.GetUsersInRoleAsync(Roles.Admin)).Count <= 1)
            throw new ValidationException("At least one administrator is required.");
        Check(await users.DeleteAsync(user));
        await audit.WriteAsync(actor.UserName, "user.delete", AuditResult.Success, target: user.UserName, clientIp: ip);
    }

    private async Task ApplyRolesAsync(IServiceProvider sp, ApplicationUser user, SaveUserRequest req)
    {
        var users = sp.GetRequiredService<UserManager<ApplicationUser>>();
        foreach (var (role, want) in new[] { (Roles.Admin, req.IsAdmin), (Roles.Auditor, req.IsAuditor) })
        {
            var has = await users.IsInRoleAsync(user, role);
            if (want && !has) Check(await users.AddToRoleAsync(user, role));
            if (!want && has) Check(await users.RemoveFromRoleAsync(user, role));
        }

        var db = sp.GetRequiredService<ApplicationDbContext>();
        var existing = await db.UserEnvironmentRoles.Where(r => r.UserId == user.Id).ToListAsync();
        db.UserEnvironmentRoles.RemoveRange(existing);
        foreach (var (envId, role) in req.EnvRoles)
            if (role is { } r && environments.ById(envId) is not null)
                db.UserEnvironmentRoles.Add(new UserEnvironmentRole { UserId = user.Id, EnvironmentId = envId, Role = r });
        await db.SaveChangesAsync();
    }

    private string Describe(SaveUserRequest req)
    {
        var roles = new List<string>();
        if (req.IsAdmin) roles.Add("Admin");
        if (req.IsAuditor) roles.Add("Auditor");
        roles.AddRange(req.EnvRoles.Where(kv => kv.Value is not null).Select(kv => $"{environments.ById(kv.Key)?.Name}:{kv.Value}"));
        return roles.Count == 0 ? "no access" : string.Join(", ", roles);
    }

    private static void RequireAdmin(UserAccess a)
    {
        if (!a.IsAdmin) throw new UnauthorizedAccessException("Administrator role required.");
    }

    private static void Check(IdentityResult r)
    {
        if (!r.Succeeded) throw new ValidationException(string.Join(" ", r.Errors.Select(e => e.Description)));
    }
}

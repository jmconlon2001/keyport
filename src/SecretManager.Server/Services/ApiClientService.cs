using System.ComponentModel.DataAnnotations;
using System.Net;
using Microsoft.EntityFrameworkCore;
using SecretManager.Core.Crypto;
using SecretManager.Core.Secrets;
using SecretManager.Server.Data;

namespace SecretManager.Server.Services;

public sealed class SaveApiClientRequest
{
    public string Name { get; set; } = "";
    public string? Description { get; set; }

    /// <summary>One grant pattern per line: exact name, <c>prefix/*</c>, or <c>*</c>.</summary>
    public string Grants { get; set; } = "";
    public string? AllowedCidrs { get; set; }
    public DateTime? ExpiresUtc { get; set; }
    public string? Reason { get; set; }
}

public sealed record ApiClientAuthResult(ApiClient? Client, string? Failure);

public sealed class ApiClientService(
    IDbContextFactory<ApplicationDbContext> dbFactory,
    EnvironmentRegistry environments,
    AuditService audit)
{
    public async Task<List<ApiClient>> ListAsync(UserAccess user, int environmentId)
    {
        if (!user.CanView(environmentId)) throw new UnauthorizedAccessException();
        await using var db = await dbFactory.CreateDbContextAsync();
        return await db.ApiClients.AsNoTracking().Include(c => c.Grants).Where(c => c.EnvironmentId == environmentId).OrderBy(c => c.Name).ToListAsync();
    }

    /// <summary>Creates a client and returns its key. The plaintext key is never stored and cannot be retrieved again.</summary>
    public async Task<(ApiClient Client, string Key)> CreateAsync(UserAccess user, int environmentId, SaveApiClientRequest req, string? clientIp)
    {
        var env = Authorize(user, environmentId, req.Reason);
        var grants = ParseGrants(req.Grants);
        ValidateCidrs(req.AllowedCidrs);
        var name = req.Name.Trim();
        if (name.Length is 0 or > 100) throw new ValidationException("Name is required (max 100 characters).");

        await using var db = await dbFactory.CreateDbContextAsync();
        if (await db.ApiClients.AnyAsync(c => c.EnvironmentId == env.Id && c.Name == name))
            throw new ValidationException($"A client named '{name}' already exists in {env.Name}.");

        var key = ApiKeys.Generate();
        var client = new ApiClient
        {
            EnvironmentId = env.Id,
            Name = name,
            Description = req.Description,
            KeyPrefix = key.Prefix,
            KeyHash = key.Hash,
            AllowedCidrs = NormalizeCidrs(req.AllowedCidrs),
            ExpiresUtc = req.ExpiresUtc,
            CreatedBy = user.UserName,
            CreatedUtc = DateTime.UtcNow,
            Grants = grants.Select(g => new ApiClientGrant { Pattern = g }).ToList(),
        };
        db.ApiClients.Add(client);
        await db.SaveChangesAsync();
        await audit.WriteAsync(user.UserName, "client.create", AuditResult.Success, env.Name, client.Name, clientIp,
            $"prefix={key.Prefix}; grants={string.Join(" ", grants)}{ReasonSuffix(req.Reason)}");
        return (client, key.Plaintext);
    }

    public async Task UpdateAsync(UserAccess user, int id, SaveApiClientRequest req, string? clientIp)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var c = await db.ApiClients.Include(x => x.Grants).FirstOrDefaultAsync(x => x.Id == id) ?? throw new KeyNotFoundException();
        var env = Authorize(user, c.EnvironmentId, req.Reason);
        var grants = ParseGrants(req.Grants);
        ValidateCidrs(req.AllowedCidrs);

        c.Description = req.Description;
        c.AllowedCidrs = NormalizeCidrs(req.AllowedCidrs);
        c.ExpiresUtc = req.ExpiresUtc;
        db.ApiClientGrants.RemoveRange(c.Grants);
        c.Grants = grants.Select(g => new ApiClientGrant { Pattern = g }).ToList();
        await db.SaveChangesAsync();
        await audit.WriteAsync(user.UserName, "client.update", AuditResult.Success, env.Name, c.Name, clientIp,
            $"grants={string.Join(" ", grants)}; cidrs={c.AllowedCidrs ?? "any"}{ReasonSuffix(req.Reason)}");
    }

    /// <summary>Issues a new key for the client; the old key stops working immediately.</summary>
    public async Task<string> RotateKeyAsync(UserAccess user, int id, string? reason, string? clientIp)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var c = await db.ApiClients.FirstOrDefaultAsync(x => x.Id == id) ?? throw new KeyNotFoundException();
        var env = Authorize(user, c.EnvironmentId, reason);
        var key = ApiKeys.Generate();
        var oldPrefix = c.KeyPrefix;
        c.KeyPrefix = key.Prefix;
        c.KeyHash = key.Hash;
        await db.SaveChangesAsync();
        await audit.WriteAsync(user.UserName, "client.rotate-key", AuditResult.Success, env.Name, c.Name, clientIp, $"{oldPrefix} -> {key.Prefix}{ReasonSuffix(reason)}");
        return key.Plaintext;
    }

    public async Task SetDisabledAsync(UserAccess user, int id, bool disabled, string? reason, string? clientIp)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var c = await db.ApiClients.FirstOrDefaultAsync(x => x.Id == id) ?? throw new KeyNotFoundException();
        var env = Authorize(user, c.EnvironmentId, reason);
        c.Disabled = disabled;
        await db.SaveChangesAsync();
        await audit.WriteAsync(user.UserName, disabled ? "client.disable" : "client.enable", AuditResult.Success, env.Name, c.Name, clientIp, ReasonSuffix(reason).TrimStart(';', ' '));
    }

    public async Task DeleteAsync(UserAccess user, int id, string? reason, string? clientIp)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var c = await db.ApiClients.FirstOrDefaultAsync(x => x.Id == id) ?? throw new KeyNotFoundException();
        var env = Authorize(user, c.EnvironmentId, reason);
        db.ApiClients.Remove(c);
        await db.SaveChangesAsync();
        await audit.WriteAsync(user.UserName, "client.delete", AuditResult.Success, env.Name, c.Name, clientIp, ReasonSuffix(reason).TrimStart(';', ' '));
    }

    /// <summary>
    /// Validates a presented key against the environment bound to the listener port. A key from another
    /// environment is rejected even if it is otherwise valid.
    /// </summary>
    public async Task<ApiClientAuthResult> AuthenticateAsync(string presentedKey, EnvironmentInfo portEnvironment, IPAddress? remoteIp, CancellationToken ct)
    {
        if (!ApiKeys.TryParsePrefix(presentedKey, out var prefix))
            return new(null, "malformed key");

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var c = await db.ApiClients.Include(x => x.Grants).FirstOrDefaultAsync(x => x.KeyPrefix == prefix, ct);
        if (c is null || !ApiKeys.Verify(presentedKey, c.KeyHash))
            return new(null, "unknown key");
        if (c.EnvironmentId != portEnvironment.Id)
            return new(c, $"key belongs to {environments.ById(c.EnvironmentId)?.Name ?? "another environment"}, presented on {portEnvironment.Name} port");
        if (c.Disabled)
            return new(c, "client disabled");
        if (c.ExpiresUtc is { } exp && exp <= DateTime.UtcNow)
            return new(c, "key expired");
        if (!IpAllowed(c.AllowedCidrs, remoteIp))
            return new(c, $"source address {remoteIp} not in allow-list");

        // Throttle LastUsed writes to once a minute per client.
        if (c.LastUsedUtc is null || c.LastUsedUtc < DateTime.UtcNow.AddMinutes(-1))
        {
            await db.ApiClients.Where(x => x.Id == c.Id).ExecuteUpdateAsync(s => s.SetProperty(x => x.LastUsedUtc, DateTime.UtcNow), ct);
        }
        return new(c, null);
    }

    public static bool IsGranted(ApiClient client, string secretName) =>
        client.Grants.Any(g => SecretNames.MatchesGrant(secretName, g.Pattern));

    public static bool IpAllowed(string? cidrs, IPAddress? ip)
    {
        if (string.IsNullOrWhiteSpace(cidrs)) return true;
        if (ip is null) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        foreach (var c in cidrs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (IPNetwork.TryParse(c, out var net) && net.Contains(ip))
                return true;
        return false;
    }

    private EnvironmentInfo Authorize(UserAccess user, int environmentId, string? reason)
    {
        var env = environments.ById(environmentId) ?? throw new KeyNotFoundException();
        if (!user.CanEdit(env.Id)) throw new UnauthorizedAccessException($"You are not allowed to manage clients in {env.Name}.");
        if (env.Protected && string.IsNullOrWhiteSpace(reason))
            throw new ValidationException($"{env.Name} is a protected environment: a reason is required.");
        return env;
    }

    private static List<string> ParseGrants(string grants)
    {
        var list = grants.Split(['\n', ',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(g => g.ToLowerInvariant()).Distinct().ToList();
        if (list.Count == 0) throw new ValidationException("At least one grant is required (e.g. billing/* or billing/oracle-main).");
        var bad = list.FirstOrDefault(g => !SecretNames.IsValidGrant(g));
        if (bad is not null) throw new ValidationException($"Invalid grant pattern '{bad}'. Use an exact name, prefix/* or *.");
        return list;
    }

    private static void ValidateCidrs(string? cidrs)
    {
        if (string.IsNullOrWhiteSpace(cidrs)) return;
        foreach (var c in cidrs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            if (!IPNetwork.TryParse(c, out _))
                throw new ValidationException($"'{c}' is not a valid CIDR (e.g. 10.20.0.0/16).");
    }

    private static string? NormalizeCidrs(string? cidrs) =>
        string.IsNullOrWhiteSpace(cidrs) ? null : string.Join(", ", cidrs.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));

    private static string ReasonSuffix(string? reason) => string.IsNullOrWhiteSpace(reason) ? "" : $"; reason: {reason.Trim()}";
}

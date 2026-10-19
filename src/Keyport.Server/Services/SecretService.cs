using System.ComponentModel.DataAnnotations;
using Microsoft.EntityFrameworkCore;
using Keyport.Core.Crypto;
using Keyport.Core.Secrets;
using Keyport.Core.Secrets.Types;
using Keyport.Server.Data;

namespace Keyport.Server.Services;

public sealed record SecretSummary(
    int Id, int EnvironmentId, string Environment, string Name, SecretType Type, string? Description, string? Tags,
    string? Host, int CurrentVersion, string UpdatedBy, DateTime UpdatedUtc, DateTime? RotateAfterUtc);

public sealed record SecretVersionInfo(int Version, string CreatedBy, DateTime CreatedUtc, string? Comment);

public sealed record SecretDetail(
    int Id, EnvironmentInfo Environment, string Name, SecretType Type, SecretMetadata Metadata, string? Tags,
    int CurrentVersion, DateTime? RotateAfterUtc, string CreatedBy, DateTime CreatedUtc, string UpdatedBy, DateTime UpdatedUtc,
    IReadOnlyList<SecretVersionInfo> Versions);

public sealed class SaveSecretRequest
{
    public string Name { get; set; } = "";
    public SecretType Type { get; set; } = SecretType.SqlServerConnection;
    public SecretMetadata Metadata { get; set; } = new();
    public string? Tags { get; set; }
    public DateTime? RotateAfterUtc { get; set; }

    /// <summary>New sensitive values. Null on update means "keep the current version".</summary>
    public SecretPayload? Payload { get; set; }
    public string? Comment { get; set; }

    /// <summary>Required for protected environments.</summary>
    public string? Reason { get; set; }
}

public sealed record ResolvedSecret(string Name, SecretType Type, SecretMetadata Metadata, SecretPayload Payload, int Version);

public sealed class SecretService(
    IDbContextFactory<ApplicationDbContext> dbFactory,
    EnvelopeEncryptor encryptor,
    EnvironmentRegistry environments,
    AuditService audit,
    ConnectionTester tester)
{
    public async Task<List<SecretSummary>> ListAsync(UserAccess user, int environmentId, string? search = null, SecretType? type = null)
    {
        Require(user.CanView(environmentId), "view this environment");
        await using var db = await dbFactory.CreateDbContextAsync();
        var q = db.Secrets.AsNoTracking().Where(s => s.EnvironmentId == environmentId);

        if (!string.IsNullOrWhiteSpace(search))
        {
            var term = search.Trim().ToLowerInvariant();
            q = q.Where(s => s.Name.Contains(term) || (s.Tags != null && s.Tags.ToLower().Contains(term)) || s.MetadataJson.ToLower().Contains(term));
        }

        var env = environments.ById(environmentId)!;
        var rows = await q.OrderBy(s => s.Name).ToListAsync();
        if (type is { } t) rows = rows.Where(s => s.Type == t).ToList(); // filtered in memory: the type is a value-converted struct
        return rows.Select(s =>
        {
            var m = s.Metadata;
            return new SecretSummary(s.Id, s.EnvironmentId, env.Name, s.Name, s.Type, m.Description, s.Tags, m.Host,
                s.CurrentVersion, s.UpdatedBy, s.UpdatedUtc, s.RotateAfterUtc);
        }).ToList();
    }

    public async Task<SecretDetail?> GetAsync(UserAccess user, int id)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var s = await db.Secrets.AsNoTracking().Include(x => x.Versions).FirstOrDefaultAsync(x => x.Id == id);
        if (s is null || !user.CanView(s.EnvironmentId)) return null;
        var env = environments.ById(s.EnvironmentId);
        if (env is null) return null;

        return new SecretDetail(s.Id, env, s.Name, s.Type, s.Metadata, s.Tags, s.CurrentVersion, s.RotateAfterUtc,
            s.CreatedBy, s.CreatedUtc, s.UpdatedBy, s.UpdatedUtc,
            s.Versions.OrderByDescending(v => v.Version).Select(v => new SecretVersionInfo(v.Version, v.CreatedBy, v.CreatedUtc, v.Comment)).ToList());
    }

    /// <summary>Decrypts the current (or a specific) version for display. Always audited.</summary>
    public async Task<SecretPayload> RevealAsync(UserAccess user, int id, string? reason, string? clientIp, int? version = null)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var s = await db.Secrets.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id) ?? throw new KeyNotFoundException();
        var env = environments.ById(s.EnvironmentId) ?? throw new KeyNotFoundException();

        if (!user.CanView(env.Id))
        {
            await audit.WriteAsync(user.UserName, "secret.reveal", AuditResult.Denied, env.Name, s.Name, clientIp);
            throw new UnauthorizedAccessException("You do not have access to this environment.");
        }
        RequireReason(env, reason);

        var v = version ?? s.CurrentVersion;
        var payload = await DecryptAsync(db, s, v);
        await audit.WriteAsync(user.UserName, "secret.reveal", AuditResult.Success, env.Name, s.Name, clientIp, Details($"v{v}", reason));
        return payload;
    }

    /// <summary>
    /// Tests a saved secret using only its STORED settings and values, never anything from an edit form, so stored
    /// passwords can only ever be sent to the server already saved with them. Protected environments need a reason.
    /// </summary>
    public async Task<ConnectionTestResult> TestStoredAsync(UserAccess user, int id, string? reason, string? clientIp, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var s = await db.Secrets.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id, ct) ?? throw new KeyNotFoundException();
        var env = environments.ById(s.EnvironmentId) ?? throw new KeyNotFoundException();
        if (!user.CanView(env.Id))
        {
            await audit.WriteAsync(user.UserName, "secret.test-connection", AuditResult.Denied, env.Name, s.Name, clientIp, ct: ct);
            throw new UnauthorizedAccessException("You do not have access to this environment.");
        }
        RequireReason(env, reason);
        if (!ConnectionTester.CanTest(s.Type)) throw new ValidationException("This kind of secret can't be tested.");

        var payload = await DecryptAsync(db, s, s.CurrentVersion);
        var result = await tester.TestAsync(s.Type, s.Metadata, payload, user.UserName, ct);
        await audit.WriteAsync(user.UserName, "secret.test-connection", result.Success ? AuditResult.Success : AuditResult.Failure, env.Name, s.Name, clientIp,
            Details($"v{s.CurrentVersion}; stored settings" + (result.Success ? "" : "; " + result.Message), reason), ct);
        return result;
    }

    public async Task<int> CreateAsync(UserAccess user, int environmentId, SaveSecretRequest req, string? clientIp)
    {
        var env = environments.ById(environmentId) ?? throw new KeyNotFoundException("Unknown environment.");
        Require(user.CanEdit(env.Id), $"edit secrets in {env.Name}");
        RequireReason(env, req.Reason);
        if (req.Payload is null) throw new ValidationException("Secret values are required.");
        req.Name = req.Name.Trim().ToLowerInvariant();
        Validate(req, req.Payload);

        await using var db = await dbFactory.CreateDbContextAsync();
        if (await db.Secrets.AnyAsync(s => s.EnvironmentId == env.Id && s.Name == req.Name))
            throw new ValidationException($"A secret named '{req.Name}' already exists in {env.Name}.");

        var (clearValues, sensitiveValues) = Prune(req.Type, req.Metadata, req.Payload);
        await using var tx = await db.Database.BeginTransactionAsync();
        var now = DateTime.UtcNow;
        var secret = new Secret
        {
            EnvironmentId = env.Id,
            Name = req.Name,
            Type = req.Type,
            MetadataJson = clearValues.ToJson(),
            Tags = NormalizeTags(req.Tags),
            RotateAfterUtc = req.RotateAfterUtc,
            CreatedBy = user.UserName,
            CreatedUtc = now,
            UpdatedBy = user.UserName,
            UpdatedUtc = now,
        };
        db.Secrets.Add(secret);
        await db.SaveChangesAsync(); // assigns Id, which is bound into the ciphertext AAD

        AddVersion(db, secret, sensitiveValues, user.UserName, req.Comment ?? "created");
        await db.SaveChangesAsync();
        await tx.CommitAsync();

        await audit.WriteAsync(user.UserName, "secret.create", AuditResult.Success, env.Name, secret.Name, clientIp, Details(req.Type.ToString(), req.Reason));
        return secret.Id;
    }

    public async Task UpdateAsync(UserAccess user, int id, SaveSecretRequest req, string? clientIp)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var s = await db.Secrets.FirstOrDefaultAsync(x => x.Id == id) ?? throw new KeyNotFoundException();
        var env = environments.ById(s.EnvironmentId) ?? throw new KeyNotFoundException();
        Require(user.CanEdit(env.Id), $"edit secrets in {env.Name}");
        RequireReason(env, req.Reason);

        // Name and type are immutable: clients reference the name, and the payload shape depends on the type.
        req.Name = s.Name;
        req.Type = s.Type;
        var effectivePayload = req.Payload ?? await DecryptAsync(db, s, s.CurrentVersion);
        Validate(req, effectivePayload);

        var (clearValues, sensitiveValues) = Prune(s.Type, req.Metadata, effectivePayload);
        s.MetadataJson = clearValues.ToJson();
        s.Tags = NormalizeTags(req.Tags);
        s.RotateAfterUtc = req.RotateAfterUtc;
        s.UpdatedBy = user.UserName;
        s.UpdatedUtc = DateTime.UtcNow;

        if (req.Payload is not null)
            AddVersion(db, s, sensitiveValues, user.UserName, req.Comment);

        await db.SaveChangesAsync();
        await audit.WriteAsync(user.UserName, req.Payload is null ? "secret.update-metadata" : "secret.update", AuditResult.Success,
            env.Name, s.Name, clientIp, Details(req.Payload is null ? null : $"v{s.CurrentVersion}", req.Reason));
    }

    /// <summary>Restores an old version by copying it forward as a new version (history is never rewritten).</summary>
    public async Task RollbackAsync(UserAccess user, int id, int version, string? reason, string? clientIp)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var s = await db.Secrets.FirstOrDefaultAsync(x => x.Id == id) ?? throw new KeyNotFoundException();
        var env = environments.ById(s.EnvironmentId) ?? throw new KeyNotFoundException();
        Require(user.CanEdit(env.Id), $"edit secrets in {env.Name}");
        RequireReason(env, reason);

        var payload = await DecryptAsync(db, s, version);
        AddVersion(db, s, payload, user.UserName, $"rollback to v{version}");
        s.UpdatedBy = user.UserName;
        s.UpdatedUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
        await audit.WriteAsync(user.UserName, "secret.rollback", AuditResult.Success, env.Name, s.Name, clientIp, Details($"v{version} -> v{s.CurrentVersion}", reason));
    }

    public async Task DeleteAsync(UserAccess user, int id, string? reason, string? clientIp)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var s = await db.Secrets.FirstOrDefaultAsync(x => x.Id == id) ?? throw new KeyNotFoundException();
        var env = environments.ById(s.EnvironmentId) ?? throw new KeyNotFoundException();
        Require(user.CanEdit(env.Id), $"delete secrets in {env.Name}");
        RequireReason(env, reason);

        db.Secrets.Remove(s);
        await db.SaveChangesAsync();
        await audit.WriteAsync(user.UserName, "secret.delete", AuditResult.Success, env.Name, s.Name, clientIp, Details(null, reason));
    }

    /// <summary>
    /// Starting point for promoting a secret to another environment: copies name, type, metadata and username.
    /// The password is intentionally NOT copied; credentials must differ per environment.
    /// </summary>
    public async Task<SaveSecretRequest> PreparePromotionAsync(UserAccess user, int id, int targetEnvironmentId, string? clientIp)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        var s = await db.Secrets.AsNoTracking().FirstOrDefaultAsync(x => x.Id == id) ?? throw new KeyNotFoundException();
        var source = environments.ById(s.EnvironmentId) ?? throw new KeyNotFoundException();
        var target = environments.ById(targetEnvironmentId) ?? throw new KeyNotFoundException();
        Require(user.CanView(source.Id), $"view {source.Name}");
        Require(user.CanEdit(target.Id), $"edit secrets in {target.Name}");

        var payload = await DecryptAsync(db, s, s.CurrentVersion);
        await audit.WriteAsync(user.UserName, "secret.promote-start", AuditResult.Success, source.Name, s.Name, clientIp, $"target={target.Name}");

        return new SaveSecretRequest
        {
            Name = s.Name,
            Type = s.Type,
            Metadata = s.Metadata.Clone(),
            Tags = s.Tags,
            Payload = SecretTypeRegistry.ForPromotion(s.Type.Definition, s.Metadata, payload).Sensitive,
            Comment = $"promoted from {source.Name}",
        };
    }

    /// <summary>Which secret names exist in which environments (no values), for spotting gaps before a promotion.</summary>
    public async Task<List<(string Name, SecretType Type, Dictionary<int, int> VersionsByEnv)>> CompareAsync(UserAccess user)
    {
        var visible = environments.All.Where(e => user.CanView(e.Id)).Select(e => e.Id).ToList();
        await using var db = await dbFactory.CreateDbContextAsync();
        var rows = await db.Secrets.AsNoTracking().Where(s => visible.Contains(s.EnvironmentId))
            .Select(s => new { s.Name, s.Type, s.EnvironmentId, s.CurrentVersion }).ToListAsync();
        return rows.GroupBy(r => r.Name).OrderBy(g => g.Key)
            .Select(g => (g.Key, g.First().Type, g.ToDictionary(r => r.EnvironmentId, r => r.CurrentVersion)))
            .ToList();
    }

    public async Task<int> CountAsync(int environmentId)
    {
        await using var db = await dbFactory.CreateDbContextAsync();
        return await db.Secrets.CountAsync(s => s.EnvironmentId == environmentId);
    }

    /// <summary>API path: resolves a secret for an authenticated client. Grant checks happen in the caller.</summary>
    public async Task<ResolvedSecret?> ResolveAsync(int environmentId, string name, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var s = await db.Secrets.AsNoTracking().FirstOrDefaultAsync(x => x.EnvironmentId == environmentId && x.Name == name, ct);
        if (s is null) return null;
        var payload = await DecryptAsync(db, s, s.CurrentVersion);
        return new ResolvedSecret(s.Name, s.Type, s.Metadata, payload, s.CurrentVersion);
    }

    public async Task<List<string>> ListNamesAsync(int environmentId, string? prefix, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var q = db.Secrets.AsNoTracking().Where(s => s.EnvironmentId == environmentId);
        if (!string.IsNullOrEmpty(prefix)) q = q.Where(s => s.Name.StartsWith(prefix));
        return await q.OrderBy(s => s.Name).Select(s => s.Name).ToListAsync(ct);
    }

    /// <summary>Re-wraps every DEK under a new KEK. Ciphertexts are untouched. Returns the number of versions re-wrapped.</summary>
    public static async Task<int> RewrapAllAsync(ApplicationDbContext db, EnvelopeEncryptor current, MasterKey newKek)
    {
        var versions = await db.SecretVersions.Include(v => v.Secret).ToListAsync();
        foreach (var v in versions)
        {
            var blob = current.Rewrap(v.ToBlob(), SecretVersion.Aad(v.SecretId, v.Secret.EnvironmentId, v.Version), newKek);
            v.WrappedDek = blob.WrappedDek;
            v.KeyId = blob.KeyId;
        }
        await db.SaveChangesAsync();
        return versions.Count;
    }

    private void AddVersion(ApplicationDbContext db, Secret s, SecretPayload payload, string actor, string? comment)
    {
        var next = s.CurrentVersion + 1;
        var blob = encryptor.EncryptString(payload.ToJson(), SecretVersion.Aad(s.Id, s.EnvironmentId, next));
        db.SecretVersions.Add(new SecretVersion
        {
            SecretId = s.Id,
            Version = next,
            WrappedDek = blob.WrappedDek,
            Ciphertext = blob.Ciphertext,
            KeyId = blob.KeyId,
            CreatedBy = actor,
            CreatedUtc = DateTime.UtcNow,
            Comment = string.IsNullOrWhiteSpace(comment) ? null : comment.Trim(),
        });
        s.CurrentVersion = next;
    }

    private async Task<SecretPayload> DecryptAsync(ApplicationDbContext db, Secret s, int version)
    {
        var v = await db.SecretVersions.AsNoTracking().FirstOrDefaultAsync(x => x.SecretId == s.Id && x.Version == version)
            ?? throw new KeyNotFoundException($"Version {version} not found.");
        if (v.KeyId != encryptor.KeyId)
            throw new InvalidOperationException($"Secret version was encrypted with master key {v.KeyId}, but the loaded key is {encryptor.KeyId}.");
        return SecretPayload.FromJson(encryptor.DecryptString(v.ToBlob(), SecretVersion.Aad(s.Id, s.EnvironmentId, version)));
    }

    /// <summary>
    /// Validates the name and, through the type's definition, every field (required, formats) and that each output
    /// renders and parses. Unknown types (definition removed) can't be created or changed.
    /// </summary>
    private static void Validate(SaveSecretRequest req, SecretPayload p)
    {
        if (!SecretNames.IsValid(req.Name))
            throw new ValidationException("Name must be lowercase path segments of letters, digits, '.', '_' or '-', e.g. billing/oracle-main.");

        var def = req.Type.Definition;
        if (def.IsUnknown)
            throw new ValidationException($"Secret type '{req.Type}' is not defined. Add its definition back to change secrets of this type.");

        var errors = SecretTypeRegistry.Current.Validate(def, SecretFields.Merge(req.Metadata, p));
        if (errors.Count > 0)
            throw new ValidationException(string.Join(" ", errors));
    }

    /// <summary>Keeps only the fields the type defines (plus the description), so values left over from switching types aren't stored.</summary>
    private static (SecretMetadata Clear, SecretPayload Sensitive) Prune(SecretType type, SecretMetadata clear, SecretPayload sensitive)
    {
        var def = type.Definition;
        if (def.IsUnknown) return (clear, sensitive);
        var merged = SecretFields.Merge(clear, sensitive);
        return SecretTypeRegistry.Split(def, merged, clear.Description);
    }

    private static void RequireReason(EnvironmentInfo env, string? reason)
    {
        if (env.Protected && string.IsNullOrWhiteSpace(reason))
            throw new ValidationException($"{env.Name} is a protected environment: a reason is required.");
    }

    private static void Require(bool allowed, string what)
    {
        if (!allowed) throw new UnauthorizedAccessException($"You are not allowed to {what}.");
    }

    private static string? NormalizeTags(string? tags) =>
        string.IsNullOrWhiteSpace(tags) ? null
            : string.Join(", ", tags.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct(StringComparer.OrdinalIgnoreCase));

    private static string? Details(string? detail, string? reason) =>
        (detail, string.IsNullOrWhiteSpace(reason) ? null : reason.Trim()) switch
        {
            (null, null) => null,
            (var d, null) => d,
            (null, var r) => $"reason: {r}",
            var (d, r) => $"{d}; reason: {r}",
        };
}

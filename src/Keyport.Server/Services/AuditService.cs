using Microsoft.EntityFrameworkCore;
using Keyport.Core.Audit;
using Keyport.Server.Data;

namespace Keyport.Server.Services;

public static class AuditResult
{
    public const string Success = "Success";
    public const string Denied = "Denied";
    public const string Failure = "Failure";
}

public sealed record AuditQuery(
    string? Actor = null, string? Action = null, string? Environment = null, string? Target = null, string? Result = null,
    DateTime? FromUtc = null, DateTime? ToUtc = null, int Skip = 0, int Take = 100);

public sealed record AuditVerification(bool Intact, long Checked, long? FirstBrokenId);

/// <summary>Append-only, hash-chained audit log. Writes are serialized so the chain stays linear (single-instance deployment).</summary>
public sealed class AuditService(IDbContextFactory<ApplicationDbContext> dbFactory, ILogger<AuditService> logger)
{
    private readonly SemaphoreSlim _lock = new(1, 1);

    public async Task WriteAsync(
        string actor, string action, string result, string? environment = null, string? target = null,
        string? clientIp = null, string? details = null, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct);
            var last = await db.AuditEvents.OrderByDescending(a => a.Id).Select(a => new { a.Id, a.Hash }).FirstOrDefaultAsync(ct);

            var id = (last?.Id ?? 0) + 1;
            var prev = last?.Hash ?? AuditChain.Genesis;
            var now = DateTime.UtcNow;
            details = Truncate(details, 2000);

            db.AuditEvents.Add(new AuditEvent
            {
                Id = id,
                TimestampUtc = now,
                Actor = actor,
                Action = action,
                Environment = environment,
                Target = target,
                Result = result,
                ClientIp = clientIp,
                Details = details,
                PrevHash = prev,
                Hash = AuditChain.ComputeHash(prev, id, now, actor, action, environment, target, result, clientIp, details),
            });
            await db.SaveChangesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Never let an audit failure be silent.
            logger.LogError(ex, "Failed to write audit event {Action} by {Actor}", action, actor);
            throw;
        }
        finally
        {
            _lock.Release();
        }
    }

    public async Task<(List<AuditEvent> Items, int Total)> QueryAsync(AuditQuery q, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        IQueryable<AuditEvent> query = db.AuditEvents.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(q.Actor)) query = query.Where(a => a.Actor.Contains(q.Actor));
        if (!string.IsNullOrWhiteSpace(q.Action)) query = query.Where(a => a.Action.Contains(q.Action));
        if (!string.IsNullOrWhiteSpace(q.Environment)) query = query.Where(a => a.Environment == q.Environment);
        if (!string.IsNullOrWhiteSpace(q.Target)) query = query.Where(a => a.Target != null && a.Target.Contains(q.Target));
        if (!string.IsNullOrWhiteSpace(q.Result)) query = query.Where(a => a.Result == q.Result);
        if (q.FromUtc is { } from) query = query.Where(a => a.TimestampUtc >= from);
        if (q.ToUtc is { } to) query = query.Where(a => a.TimestampUtc <= to);

        var total = await query.CountAsync(ct);
        var items = await query.OrderByDescending(a => a.Id).Skip(q.Skip).Take(q.Take).ToListAsync(ct);
        return (items, total);
    }

    /// <summary>
    /// Deletes audit events older than the cutoff. The hash and id of the last deleted event are stored as the
    /// chain anchor so the remaining records can still be verified.
    /// </summary>
    public async Task<int> PurgeOlderThanAsync(DateTime cutoffUtc, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct);
            // Never purge the newest event: the chain head must stay in the table.
            var maxId = await db.AuditEvents.MaxAsync(a => (long?)a.Id, ct) ?? 0;
            var last = await db.AuditEvents.Where(a => a.TimestampUtc < cutoffUtc && a.Id < maxId)
                .OrderByDescending(a => a.Id).Select(a => new { a.Id, a.Hash }).FirstOrDefaultAsync(ct);
            if (last is null) return 0;

            await using var tx = await db.Database.BeginTransactionAsync(ct);
            await SetAnchorAsync(db, last.Id, last.Hash, ct);
            var deleted = await db.AuditEvents.Where(a => a.Id <= last.Id).ExecuteDeleteAsync(ct);
            await tx.CommitAsync(ct);
            return deleted;
        }
        finally
        {
            _lock.Release();
        }
    }

    private const string AnchorKey = "audit.anchor";

    private static async Task<(long Id, string Hash)> GetAnchorAsync(ApplicationDbContext db, CancellationToken ct)
    {
        var s = await db.AppSettings.AsNoTracking().FirstOrDefaultAsync(x => x.Key == AnchorKey, ct);
        if (s is null) return (0, AuditChain.Genesis);
        var parts = s.Value.Split(':');
        return (long.Parse(parts[0]), parts[1]);
    }

    private static async Task SetAnchorAsync(ApplicationDbContext db, long id, string hash, CancellationToken ct)
    {
        var s = await db.AppSettings.FirstOrDefaultAsync(x => x.Key == AnchorKey, ct);
        if (s is null) db.AppSettings.Add(new AppSetting { Key = AnchorKey, Value = $"{id}:{hash}" });
        else s.Value = $"{id}:{hash}";
        await db.SaveChangesAsync(ct);
    }

    public async Task<AuditVerification> VerifyAsync(CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var (anchorId, anchorHash) = await GetAnchorAsync(db, ct);
        var prev = anchorHash;
        long checkedCount = 0;
        long lastId = anchorId;
        const int batch = 5000;

        while (true)
        {
            var rows = await db.AuditEvents.AsNoTracking().Where(a => a.Id > lastId).OrderBy(a => a.Id).Take(batch).ToListAsync(ct);
            if (rows.Count == 0) break;

            // Ids are dense; a gap means a row was deleted.
            foreach (var r in rows)
            {
                if (r.Id != lastId + 1)
                    return new AuditVerification(false, checkedCount, lastId + 1);
                lastId = r.Id;
            }

            var broken = AuditChain.FindFirstBreak(rows, prev);
            if (broken is not null)
                return new AuditVerification(false, checkedCount, broken);

            checkedCount += rows.Count;
            prev = rows[^1].Hash;
        }
        return new AuditVerification(true, checkedCount, null);
    }

    private static string? Truncate(string? s, int max) => s is null || s.Length <= max ? s : s[..max];
}

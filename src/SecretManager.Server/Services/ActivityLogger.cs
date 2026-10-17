using System.Collections.Concurrent;
using System.Threading.Channels;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecretManager.Server.Configuration;
using SecretManager.Server.Data;

namespace SecretManager.Server.Services;

public sealed record ActivityQuery(
    string? Source = null, string? Environment = null, string? Actor = null, string? Path = null, int? MinStatus = null,
    DateTime? FromUtc = null, DateTime? ToUtc = null, int Skip = 0, int Take = 100);

/// <summary>
/// Records every API request and UI action. Writes are queued and flushed in batches by a background
/// service so request latency is unaffected. Also keeps in-memory metrics for the status page.
/// </summary>
public sealed class ActivityLogger(IDbContextFactory<ApplicationDbContext> dbFactory)
{
    private readonly Channel<ActivityLog> _queue = Channel.CreateBounded<ActivityLog>(
        new BoundedChannelOptions(50_000) { FullMode = BoundedChannelFullMode.Wait, SingleReader = true });

    public RequestMetrics Metrics { get; } = new();

    internal ChannelReader<ActivityLog> Reader => _queue.Reader;

    public void Log(ActivityLog entry)
    {
        entry.TimestampUtc = entry.TimestampUtc == default ? DateTime.UtcNow : entry.TimestampUtc;
        entry.Path = Truncate(entry.Path, 500)!;
        entry.UserAgent = Truncate(entry.UserAgent, 300);
        entry.Error = Truncate(entry.Error, 1000);
        if (entry.Source == LogSource.Api)
            Metrics.Record(entry.Environment ?? "-", entry.StatusCode, entry.DurationMs);

        if (!_queue.Writer.TryWrite(entry))
            Interlocked.Increment(ref _dropped);
    }

    private long _dropped;

    /// <summary>Entries that could not be queued (backlog full or shutting down). Surfaced as a health warning.</summary>
    public long Dropped => Interlocked.Read(ref _dropped);

    public int Backlog => _queue.Reader.Count;

    internal void Complete() => _queue.Writer.TryComplete();

    public void LogUi(string actor, string action, string path, string? target = null, string? environment = null, string? clientIp = null, int status = 200, string? error = null) =>
        Log(new ActivityLog
        {
            Source = LogSource.Ui,
            Actor = actor,
            Action = action,
            Path = path,
            Target = target,
            Environment = environment,
            ClientIp = clientIp,
            StatusCode = status,
            Error = error,
        });

    public async Task<(List<ActivityLog> Items, int Total)> QueryAsync(ActivityQuery q, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        IQueryable<ActivityLog> query = db.ActivityLogs.AsNoTracking();
        if (!string.IsNullOrWhiteSpace(q.Source)) query = query.Where(a => a.Source == q.Source);
        if (!string.IsNullOrWhiteSpace(q.Environment)) query = query.Where(a => a.Environment == q.Environment);
        if (!string.IsNullOrWhiteSpace(q.Actor)) query = query.Where(a => a.Actor != null && a.Actor.Contains(q.Actor));
        if (!string.IsNullOrWhiteSpace(q.Path)) query = query.Where(a => a.Path.Contains(q.Path) || (a.Target != null && a.Target.Contains(q.Path)));
        if (q.MinStatus is { } ms) query = query.Where(a => a.StatusCode >= ms);
        if (q.FromUtc is { } from) query = query.Where(a => a.TimestampUtc >= from);
        if (q.ToUtc is { } to) query = query.Where(a => a.TimestampUtc <= to);

        var total = await query.CountAsync(ct);
        var items = await query.OrderByDescending(a => a.Id).Skip(q.Skip).Take(q.Take).ToListAsync(ct);
        return (items, total);
    }

    /// <summary>Per-environment API request counts over the trailing window, from the persisted log.</summary>
    public async Task<List<EnvironmentTraffic>> TrafficAsync(TimeSpan window, CancellationToken ct = default)
    {
        var since = DateTime.UtcNow - window;
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        return await db.ActivityLogs.AsNoTracking()
            .Where(a => a.Source == LogSource.Api && a.TimestampUtc >= since)
            .GroupBy(a => a.Environment ?? "-")
            .Select(g => new EnvironmentTraffic(
                g.Key,
                g.Count(),
                g.Count(a => a.StatusCode >= 400 && a.StatusCode < 500),
                g.Count(a => a.StatusCode >= 500),
                g.Average(a => a.DurationMs)))
            .ToListAsync(ct);
    }

    private static string? Truncate(string? s, int max) => s is null || s.Length <= max ? s : s[..max];
}

public sealed record EnvironmentTraffic(string Environment, int Requests, int ClientErrors, int ServerErrors, double AvgMs);

/// <summary>In-memory request metrics since process start (per environment), including recent latency percentiles.</summary>
public sealed class RequestMetrics
{
    private readonly ConcurrentDictionary<string, EnvCounters> _byEnv = new();
    public DateTime StartedUtc { get; } = DateTime.UtcNow;

    public void Record(string env, int status, double ms) => _byEnv.GetOrAdd(env, _ => new EnvCounters()).Record(status, ms);

    public IReadOnlyDictionary<string, EnvSnapshot> Snapshot() =>
        _byEnv.ToDictionary(kv => kv.Key, kv => kv.Value.Snapshot());

    private sealed class EnvCounters
    {
        private readonly Lock _gate = new();
        private readonly double[] _ring = new double[1000];
        private int _ringCount, _ringPos;
        private long _total, _errors4, _errors5;
        private DateTime? _lastUtc;

        public void Record(int status, double ms)
        {
            lock (_gate)
            {
                _total++;
                if (status is >= 400 and < 500) _errors4++;
                if (status >= 500) _errors5++;
                _ring[_ringPos] = ms;
                _ringPos = (_ringPos + 1) % _ring.Length;
                _ringCount = Math.Min(_ringCount + 1, _ring.Length);
                _lastUtc = DateTime.UtcNow;
            }
        }

        public EnvSnapshot Snapshot()
        {
            lock (_gate)
            {
                var sample = _ring.Take(_ringCount).Order().ToArray();
                double P(double p) => sample.Length == 0 ? 0 : sample[Math.Min(sample.Length - 1, (int)Math.Ceiling(p * sample.Length) - 1)];
                return new EnvSnapshot(_total, _errors4, _errors5, P(0.5), P(0.95), P(0.99), _lastUtc);
            }
        }
    }
}

public sealed record EnvSnapshot(long Total, long ClientErrors, long ServerErrors, double P50Ms, double P95Ms, double P99Ms, DateTime? LastRequestUtc);

/// <summary>Drains the activity queue into the database in batches.</summary>
public sealed class ActivityLogWriter(ActivityLogger activity, IDbContextFactory<ApplicationDbContext> dbFactory, ILogger<ActivityLogWriter> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // On shutdown, stop accepting entries and drain what is queued.
        await using var _ = stoppingToken.Register(activity.Complete);
        var batch = new List<ActivityLog>(500);
        while (await activity.Reader.WaitToReadAsync(CancellationToken.None))
        {
            while (batch.Count < 500 && activity.Reader.TryRead(out var e)) batch.Add(e);
            try
            {
                await using var db = await dbFactory.CreateDbContextAsync(CancellationToken.None);
                db.ActivityLogs.AddRange(batch);
                await db.SaveChangesAsync(CancellationToken.None);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Failed to persist {Count} activity log entries", batch.Count);
            }
            batch.Clear();

            if (!stoppingToken.IsCancellationRequested) await Task.Delay(250, CancellationToken.None);
        }
    }
}

/// <summary>Applies the configured retention to the activity and audit logs.</summary>
public sealed class LogRetentionService(
    IDbContextFactory<ApplicationDbContext> dbFactory,
    AuditService audit,
    IOptions<SecretManagerOptions> options,
    JobStatus jobs,
    ILogger<LogRetentionService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await PurgeAsync(stoppingToken);
                jobs.Report("log-retention", true, null);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Log retention purge failed");
                jobs.Report("log-retention", false, ex.Message);
            }
            await Task.Delay(TimeSpan.FromHours(Math.Max(1, options.Value.Logs.PurgeIntervalHours)), stoppingToken);
        }
    }

    public async Task PurgeAsync(CancellationToken ct)
    {
        var o = options.Value.Logs;
        var now = DateTime.UtcNow;
        int api = 0, ui = 0, aud = 0;

        await using (var db = await dbFactory.CreateDbContextAsync(ct))
        {
            if (o.ApiLogRetentionDays > 0)
            {
                var cutoff = now.AddDays(-o.ApiLogRetentionDays);
                api = await db.ActivityLogs.Where(a => a.Source == LogSource.Api && a.TimestampUtc < cutoff).ExecuteDeleteAsync(ct);
            }
            if (o.UiLogRetentionDays > 0)
            {
                var cutoff = now.AddDays(-o.UiLogRetentionDays);
                ui = await db.ActivityLogs.Where(a => a.Source == LogSource.Ui && a.TimestampUtc < cutoff).ExecuteDeleteAsync(ct);
            }
        }
        if (o.AuditRetentionDays > 0)
            aud = await audit.PurgeOlderThanAsync(now.AddDays(-o.AuditRetentionDays), ct);

        if (api + ui + aud > 0)
        {
            logger.LogInformation("Retention purge removed {Api} API, {Ui} UI and {Audit} audit entries", api, ui, aud);
            await audit.WriteAsync("system", "logs.purge", AuditResult.Success,
                details: $"api={api} (>{o.ApiLogRetentionDays}d); ui={ui} (>{o.UiLogRetentionDays}d); audit={aud} (>{o.AuditRetentionDays}d)", ct: ct);
        }
    }
}

/// <summary>Last-run status of background jobs, surfaced on the health and status pages.</summary>
public sealed class JobStatus
{
    private readonly ConcurrentDictionary<string, JobRun> _runs = new();
    public void Report(string job, bool ok, string? error) => _runs[job] = new JobRun(job, ok, DateTime.UtcNow, error);
    public IReadOnlyCollection<JobRun> All => _runs.Values.OrderBy(r => r.Job).ToList();
}

public sealed record JobRun(string Job, bool Ok, DateTime LastRunUtc, string? Error);

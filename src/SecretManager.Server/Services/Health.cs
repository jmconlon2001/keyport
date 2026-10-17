using System.Reflection;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using SecretManager.Core.Crypto;
using SecretManager.Server.Configuration;
using SecretManager.Server.Data;

namespace SecretManager.Server.Services;

public sealed class DatabaseHealthCheck(IDbContextFactory<ApplicationDbContext> dbFactory) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        try
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct);
            var envs = await db.Environments.CountAsync(ct);
            return HealthCheckResult.Healthy($"SQLite reachable; {envs} environments.");
        }
        catch (Exception ex)
        {
            return HealthCheckResult.Unhealthy("Database unreachable.", ex);
        }
    }
}

/// <summary>Confirms the loaded master key is the one existing secrets were encrypted with.</summary>
public sealed class MasterKeyHealthCheck(IDbContextFactory<ApplicationDbContext> dbFactory, EnvelopeEncryptor encryptor) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var foreign = await db.SecretVersions.CountAsync(v => v.KeyId != encryptor.KeyId, ct);
        var data = new Dictionary<string, object> { ["keyId"] = encryptor.KeyId };
        return foreign == 0
            ? HealthCheckResult.Healthy($"Master key {encryptor.KeyId} loaded.", data)
            : HealthCheckResult.Unhealthy($"{foreign} secret versions were encrypted with a different master key.", data: data);
    }
}

public sealed class CertificateHealthCheck(CertificateManager certs) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        var server = certs.ServerCertificate;
        var anchor = certs.TrustAnchor;
        var serverDays = (server.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays;
        var anchorDays = (anchor.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays;
        var data = new Dictionary<string, object>
        {
            ["serverNotAfter"] = server.NotAfter.ToUniversalTime(),
            ["trustAnchorNotAfter"] = anchor.NotAfter.ToUniversalTime(),
        };

        if (serverDays <= 0 || anchorDays <= 0)
            return Task.FromResult(HealthCheckResult.Unhealthy("A certificate has expired.", data: data));
        if (serverDays < 14)
            return Task.FromResult(HealthCheckResult.Degraded($"Server certificate expires in {serverDays:0} days; renewal is overdue.", data: data));
        if (anchorDays < 180)
            return Task.FromResult(HealthCheckResult.Degraded($"CA certificate expires in {anchorDays:0} days; plan a CA rollover.", data: data));
        return Task.FromResult(HealthCheckResult.Healthy($"Server certificate valid for {serverDays:0} more days.", data));
    }
}

public sealed class DiskSpaceHealthCheck(IOptions<SecretManagerOptions> options) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        var drive = new DriveInfo(Path.GetFullPath(options.Value.DataPath));
        var freeMb = drive.AvailableFreeSpace / 1024 / 1024;
        var data = new Dictionary<string, object> { ["freeMb"] = freeMb, ["totalMb"] = drive.TotalSize / 1024 / 1024 };
        return Task.FromResult(freeMb switch
        {
            < 100 => HealthCheckResult.Unhealthy($"Only {freeMb} MB free on the data volume.", data: data),
            < 1024 => HealthCheckResult.Degraded($"{freeMb} MB free on the data volume.", data: data),
            _ => HealthCheckResult.Healthy($"{freeMb:N0} MB free on the data volume.", data),
        });
    }
}

public sealed class AuditChainHealthCheck(AuditIntegrityMonitor monitor) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        var r = monitor.Last;
        if (r is null) return Task.FromResult(HealthCheckResult.Healthy("Audit chain not verified yet (runs shortly after startup)."));
        return Task.FromResult(r.Value.Result.Intact
            ? HealthCheckResult.Healthy($"Audit chain intact ({r.Value.Result.Checked:N0} events, checked {r.Value.AtUtc:u}).")
            : HealthCheckResult.Unhealthy($"Audit chain broken at event #{r.Value.Result.FirstBrokenId} (checked {r.Value.AtUtc:u})."));
    }
}

public sealed class BackgroundJobsHealthCheck(JobStatus jobs, ActivityLogger activity) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default)
    {
        var failed = jobs.All.Where(j => !j.Ok).ToList();
        var data = new Dictionary<string, object> { ["activityBacklog"] = activity.Backlog, ["activityDropped"] = activity.Dropped };
        if (failed.Count > 0)
            return Task.FromResult(HealthCheckResult.Degraded($"Failing: {string.Join(", ", failed.Select(f => $"{f.Job} ({f.Error})"))}", data: data));
        if (activity.Dropped > 0)
            return Task.FromResult(HealthCheckResult.Degraded($"{activity.Dropped} activity log entries were dropped (backlog full).", data: data));
        return Task.FromResult(HealthCheckResult.Healthy($"{jobs.All.Count} background jobs OK.", data));
    }
}

/// <summary>Re-verifies the audit hash chain hourly; result feeds the health check and the UI.</summary>
public sealed class AuditIntegrityMonitor(AuditService audit, JobStatus jobs, ILogger<AuditIntegrityMonitor> logger) : BackgroundService
{
    public (AuditVerification Result, DateTime AtUtc)? Last { get; private set; }

    public async Task<AuditVerification> RunAsync(CancellationToken ct = default)
    {
        var r = await audit.VerifyAsync(ct);
        Last = (r, DateTime.UtcNow);
        if (!r.Intact) logger.LogCritical("Audit chain verification FAILED at event #{Id}", r.FirstBrokenId);
        return r;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(10), stoppingToken);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var r = await RunAsync(stoppingToken);
                jobs.Report("audit-verification", r.Intact, r.Intact ? null : $"broken at #{r.FirstBrokenId}");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Audit verification failed to run");
                jobs.Report("audit-verification", false, ex.Message);
            }
            await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
        }
    }
}

public static class HealthResponse
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static object ToDto(HealthReport report) => new
    {
        status = report.Status.ToString(),
        totalDurationMs = Math.Round(report.TotalDuration.TotalMilliseconds, 1),
        checkedUtc = DateTime.UtcNow,
        checks = report.Entries.Select(e => new
        {
            name = e.Key,
            status = e.Value.Status.ToString(),
            description = e.Value.Description,
            durationMs = Math.Round(e.Value.Duration.TotalMilliseconds, 1),
            data = e.Value.Data.Count == 0 ? null : e.Value.Data,
        }),
    };

    public static Task WriteAsync(HttpContext ctx, HealthReport report)
    {
        ctx.Response.ContentType = "application/json";
        return ctx.Response.WriteAsync(JsonSerializer.Serialize(ToDto(report), Json));
    }
}

public sealed record ListenerStatus(string Name, string Kind, int Port, bool Protected, string Color, int Secrets, int Clients, EnvSnapshot? SinceStart, EnvironmentTraffic? Last24h);

public sealed record SystemStatus(
    string Version, DateTime StartedUtc, TimeSpan Uptime, string Health, string MasterKeyId,
    DateTime ServerCertNotAfter, DateTime TrustAnchorNotAfter, string TrustAnchorFingerprint, IReadOnlyList<string> CertificateNames,
    IReadOnlyList<ListenerStatus> Listeners, IReadOnlyCollection<JobRun> Jobs,
    long DatabaseBytes, int ActivityBacklog, long ActivityDropped, LogOptions Retention);

/// <summary>Builds the operational status snapshot used by the Status page and status APIs.</summary>
public sealed class StatusService(
    EnvironmentRegistry environments,
    CertificateManager certs,
    ActivityLogger activity,
    JobStatus jobs,
    HealthCheckService health,
    EnvelopeEncryptor encryptor,
    IDbContextFactory<ApplicationDbContext> dbFactory,
    IOptions<SecretManagerOptions> options)
{
    public static string Version { get; } =
        typeof(StatusService).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion?.Split('+')[0] ?? "dev";

    public async Task<SystemStatus> GetAsync(CancellationToken ct = default)
    {
        var report = await health.CheckHealthAsync(ct);
        var metrics = activity.Metrics.Snapshot();
        var traffic = (await activity.TrafficAsync(TimeSpan.FromDays(1), ct)).ToDictionary(t => t.Environment);

        await using var db = await dbFactory.CreateDbContextAsync(ct);
        var secretCounts = await db.Secrets.GroupBy(s => s.EnvironmentId).Select(g => new { g.Key, C = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.C, ct);
        var clientCounts = await db.ApiClients.Where(c => !c.Disabled).GroupBy(c => c.EnvironmentId).Select(g => new { g.Key, C = g.Count() }).ToDictionaryAsync(x => x.Key, x => x.C, ct);

        var listeners = new List<ListenerStatus>();
        if (environments.HttpPort > 0)
            listeners.Add(new ListenerStatus("HTTP bootstrap", "http", environments.HttpPort, false, "#64748b", 0, 0, null, null));
        listeners.Add(new ListenerStatus("Admin UI", "admin", environments.AdminPort, false, "#6366f1", 0, 0, null, null));
        listeners.AddRange(environments.All.Select(e => new ListenerStatus(
            e.Name, "environment", e.Port, e.Protected, e.Color,
            secretCounts.GetValueOrDefault(e.Id), clientCounts.GetValueOrDefault(e.Id),
            metrics.GetValueOrDefault(e.Name), traffic.GetValueOrDefault(e.Name))));

        var dbPath = Path.Combine(options.Value.DataPath, "secretmanager.db");
        var dbBytes = File.Exists(dbPath) ? new FileInfo(dbPath).Length : 0;

        return new SystemStatus(
            Version, activity.Metrics.StartedUtc, DateTime.UtcNow - activity.Metrics.StartedUtc, report.Status.ToString(), encryptor.KeyId,
            certs.ServerCertificate.NotAfter.ToUniversalTime(), certs.TrustAnchor.NotAfter.ToUniversalTime(),
            Core.Pki.CertificateAuthority.Sha256Fingerprint(certs.TrustAnchor), certs.SubjectAlternativeNames,
            listeners, jobs.All, dbBytes, activity.Backlog, activity.Dropped, options.Value.Logs);
    }
}

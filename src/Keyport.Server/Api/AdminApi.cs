using System.Globalization;
using System.Text;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Keyport.Server.Data;
using Keyport.Server.Services;

namespace Keyport.Server.Api;

/// <summary>Admin-port API used by the UI for downloads and by monitoring tools (cookie-authenticated).</summary>
public static class AdminApi
{
    public const string AuditPolicy = "AuditReader";

    public static void MapAdminApi(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/admin/api").WithTags("Admin API").RequireAuthorization();

        // Keeps the sign-in cookie alive while someone is actively using an open tab (called by app.js).
        admin.MapGet("/ping", () => Results.NoContent()).ExcludeFromDescription();
        admin.MapGet("/status", (StatusService status, CancellationToken ct) => status.GetAsync(ct))
            .WithSummary("Operational status: listeners, traffic, certificates, jobs.");

        admin.MapGet("/health", async (HealthCheckService health, CancellationToken ct) =>
            Results.Json(HealthResponse.ToDto(await health.CheckHealthAsync(ct)), HealthResponse.Json))
            .WithSummary("Detailed health report.");

        var audit = admin.MapGroup("").RequireAuthorization(AuditPolicy);

        audit.MapGet("/audit", async (AuditService svc, [AsParameters] AuditFilter f, CancellationToken ct) =>
        {
            var (items, total) = await svc.QueryAsync(f.ToQuery(), ct);
            return Results.Ok(new { total, items });
        }).WithSummary("Query the audit log.");

        audit.MapGet("/audit/verify", async (AuditIntegrityMonitor monitor, CancellationToken ct) => await monitor.RunAsync(ct))
            .WithSummary("Verify the audit hash chain now.");

        audit.MapGet("/audit/export.csv", async (AuditService svc, [AsParameters] AuditFilter f, HttpContext ctx, CancellationToken ct) =>
        {
            var (items, _) = await svc.QueryAsync(f.ToQuery() with { Take = 100_000 }, ct);
            var csv = Csv(["Id", "TimestampUtc", "Actor", "Action", "Environment", "Target", "Result", "ClientIp", "Details", "Hash"],
                items.Select(a => new object?[] { a.Id, a.TimestampUtc, a.Actor, a.Action, a.Environment, a.Target, a.Result, a.ClientIp, a.Details, a.Hash }));
            await svc.WriteAsync(ctx.User.Identity!.Name!, "audit.export", AuditResult.Success, clientIp: ctx.Connection.RemoteIpAddress?.ToString(), details: $"{items.Count} rows", ct: ct);
            return Results.File(csv, "text/csv", $"audit-{DateTime.UtcNow:yyyyMMdd-HHmmss}.csv");
        }).WithSummary("Export the audit log as CSV.");

        audit.MapGet("/activity", async (ActivityLogger svc, [AsParameters] ActivityFilter f, CancellationToken ct) =>
        {
            var (items, total) = await svc.QueryAsync(f.ToQuery(), ct);
            return Results.Ok(new { total, items });
        }).WithSummary("Query the API request / UI activity log.");

        audit.MapGet("/activity/export.csv", async (ActivityLogger svc, AuditService auditSvc, [AsParameters] ActivityFilter f, HttpContext ctx, CancellationToken ct) =>
        {
            var (items, _) = await svc.QueryAsync(f.ToQuery() with { Take = 100_000 }, ct);
            var csv = Csv(["Id", "TimestampUtc", "Source", "Environment", "Actor", "Method", "Path", "Target", "Status", "DurationMs", "ClientIp", "UserAgent", "Error"],
                items.Select(a => new object?[] { a.Id, a.TimestampUtc, a.Source, a.Environment, a.Actor, a.Method, a.Path, a.Target, a.StatusCode, a.DurationMs, a.ClientIp, a.UserAgent, a.Error }));
            await auditSvc.WriteAsync(ctx.User.Identity!.Name!, "activity.export", AuditResult.Success, clientIp: ctx.Connection.RemoteIpAddress?.ToString(), details: $"{items.Count} rows", ct: ct);
            return Results.File(csv, "text/csv", $"activity-{DateTime.UtcNow:yyyyMMdd-HHmmss}.csv");
        }).WithSummary("Export the activity log as CSV.");
    }

    public sealed record AuditFilter(string? Actor, string? Action, string? Environment, string? Target, string? Result, DateTime? From, DateTime? To, int? Skip, int? Take)
    {
        public AuditQuery ToQuery() => new(Actor, Action, Environment, Target, Result, From?.ToUniversalTime(), To?.ToUniversalTime(), Skip ?? 0, Math.Clamp(Take ?? 100, 1, 1000));
    }

    public sealed record ActivityFilter(string? Source, string? Environment, string? Actor, string? Path, int? MinStatus, DateTime? From, DateTime? To, int? Skip, int? Take)
    {
        public ActivityQuery ToQuery() => new(Source, Environment, Actor, Path, MinStatus, From?.ToUniversalTime(), To?.ToUniversalTime(), Skip ?? 0, Math.Clamp(Take ?? 100, 1, 1000));
    }

    private static byte[] Csv(string[] header, IEnumerable<object?[]> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine(string.Join(',', header));
        foreach (var r in rows)
            sb.AppendLine(string.Join(',', r.Select(Field)));
        return Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(sb.ToString())).ToArray();

        static string Field(object? v)
        {
            var s = v switch
            {
                null => "",
                DateTime d => d.ToString("O", CultureInfo.InvariantCulture),
                IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
                _ => v.ToString() ?? "",
            };
            // Neutralise spreadsheet formula injection.
            if (s.Length > 0 && "=+-@\t\r".Contains(s[0])) s = "'" + s;
            return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
        }
    }
}

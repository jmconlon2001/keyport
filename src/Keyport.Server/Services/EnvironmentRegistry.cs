using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Keyport.Server.Configuration;
using Keyport.Server.Data;

namespace Keyport.Server.Services;

public sealed record EnvironmentInfo(int Id, string Name, int Port, string Color, bool Protected, int SortOrder);

/// <summary>
/// The configured environments, keyed by listener port. Configuration is the source of truth; the database
/// rows are synced on startup so secrets keep stable foreign keys.
/// </summary>
public sealed class EnvironmentRegistry(IOptions<KeyportOptions> options)
{
    private IReadOnlyList<EnvironmentInfo> _all = [];
    private Dictionary<int, EnvironmentInfo> _byPort = [];

    public IReadOnlyList<EnvironmentInfo> All => _all;
    public int AdminPort => options.Value.Edge.AdminPort;
    public int HttpPort => options.Value.Edge.HttpPort;

    public EnvironmentInfo? ByPort(int port) => _byPort.GetValueOrDefault(port);
    public EnvironmentInfo? ById(int id) => _all.FirstOrDefault(e => e.Id == id);
    public EnvironmentInfo? ByName(string? name) => _all.FirstOrDefault(e => string.Equals(e.Name, name, StringComparison.OrdinalIgnoreCase));

    /// <summary>Next environment in promotion order (Dev → Test → Upgrade → Prod), if any.</summary>
    public EnvironmentInfo? Next(EnvironmentInfo env) => _all.FirstOrDefault(e => e.SortOrder > env.SortOrder);

    public static void Validate(KeyportOptions o)
    {
        if (o.Environments.Count == 0)
            throw new InvalidOperationException("At least one environment must be configured under Keyport:Environments.");

        var ports = o.Environments.Select(e => e.Port).Append(o.Edge.AdminPort).ToList();
        if (o.Edge.HttpPort > 0) ports.Add(o.Edge.HttpPort);
        var dup = ports.GroupBy(p => p).FirstOrDefault(g => g.Count() > 1);
        if (dup is not null)
            throw new InvalidOperationException($"Port {dup.Key} is assigned more than once. Every environment needs its own port.");

        var dupName = o.Environments.GroupBy(e => e.Name, StringComparer.OrdinalIgnoreCase).FirstOrDefault(g => g.Count() > 1);
        if (dupName is not null)
            throw new InvalidOperationException($"Environment '{dupName.Key}' is configured more than once.");

        foreach (var e in o.Environments)
        {
            if (string.IsNullOrWhiteSpace(e.Name) || e.Name.Length > 50)
                throw new InvalidOperationException("Environment names must be 1-50 characters.");
            if (e.Port is <= 0 or > 65535)
                throw new InvalidOperationException($"Environment '{e.Name}' has invalid port {e.Port}.");
        }
    }

    public async Task SyncAsync(ApplicationDbContext db, CancellationToken ct = default)
    {
        var configured = options.Value.Environments;
        var existing = await db.Environments.ToListAsync(ct);

        for (var i = 0; i < configured.Count; i++)
        {
            var c = configured[i];
            var row = existing.FirstOrDefault(e => string.Equals(e.Name, c.Name, StringComparison.OrdinalIgnoreCase));
            if (row is null)
            {
                row = new EnvironmentDef { Name = c.Name };
                db.Environments.Add(row);
                existing.Add(row);
            }
            row.Port = c.Port;
            row.Color = c.Color;
            row.Protected = c.Protected;
            row.SortOrder = i;
            row.Active = true;
        }

        foreach (var orphan in existing.Where(e => !configured.Any(c => string.Equals(c.Name, e.Name, StringComparison.OrdinalIgnoreCase))))
            orphan.Active = false;

        await db.SaveChangesAsync(ct);

        _all = existing.Where(e => e.Active)
            .OrderBy(e => e.SortOrder)
            .Select(e => new EnvironmentInfo(e.Id, e.Name, e.Port, e.Color, e.Protected, e.SortOrder))
            .ToList();
        _byPort = _all.ToDictionary(e => e.Port);
    }
}

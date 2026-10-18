using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.RegularExpressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Keyport.Server.Api;
using Keyport.Server.Configuration;
using Keyport.Server.Data;
using Yarp.ReverseProxy;
using Yarp.ReverseProxy.Configuration;
using Yarp.ReverseProxy.Health;
using Yarp.ReverseProxy.Model;

namespace Keyport.Server.Services;

/// <summary>
/// Supplies UI-managed routes to YARP. Works alongside the configuration provider (appsettings
/// "ReverseProxy" section); ids are prefixed "ui-" so the two never collide. <see cref="Reload"/> swaps the
/// snapshot and signals YARP, so changes apply without a restart.
/// </summary>
public sealed class DbProxyConfigProvider(IDbContextFactory<ApplicationDbContext> dbFactory) : IProxyConfigProvider
{
    public const string IdPrefix = "ui-";
    public const string PortsKey = "Ports";
    public const string RelaxCspKey = "RelaxCsp";

    private volatile Snapshot _current = new([], []);

    public IProxyConfig GetConfig() => _current;

    public void Reload()
    {
        using var db = dbFactory.CreateDbContext();
        var routes = db.ProxyRoutes.AsNoTracking().Where(r => r.Enabled).ToList();
        var yarpRoutes = new List<RouteConfig>();
        var clusters = new List<ClusterConfig>();
        foreach (var r in routes)
        {
            var (route, cluster) = ToYarp(r);
            yarpRoutes.Add(route);
            clusters.Add(cluster);
        }

        var old = _current;
        _current = new Snapshot(yarpRoutes, clusters);
        old.SignalChange();
    }

    public static (RouteConfig Route, ClusterConfig Cluster) ToYarp(ProxyRoute r)
    {
        var id = IdPrefix + r.Name;
        var route = new RouteConfig
        {
            RouteId = id,
            ClusterId = id,
            Match = new RouteMatch { Path = r.PathPrefix + "/{**rest}" },
            AuthorizationPolicy = r.Access switch
            {
                ProxyAccess.Anonymous => "anonymous",
                ProxyAccess.SignedIn => "default",
                ProxyAccess.Auditors => AdminApi.AuditPolicy,
                _ => Roles.Admin,
            },
            Metadata = new Dictionary<string, string>
            {
                [PortsKey] = r.Ports,
                [RelaxCspKey] = r.RelaxCsp ? "true" : "false",
            },
            Transforms = r.StripPrefix ? [new Dictionary<string, string> { ["PathRemovePrefix"] = r.PathPrefix }] : null,
        };

        var cluster = new ClusterConfig
        {
            ClusterId = id,
            LoadBalancingPolicy = r.LoadBalancing,
            Destinations = r.DestinationList.Select((d, i) => (d, i))
                .ToDictionary(x => $"d{x.i + 1}", x => new DestinationConfig { Address = x.d }),
            HealthCheck = string.IsNullOrWhiteSpace(r.HealthCheckPath) ? null : new HealthCheckConfig
            {
                Active = new ActiveHealthCheckConfig
                {
                    Enabled = true,
                    Interval = TimeSpan.FromSeconds(30),
                    Timeout = TimeSpan.FromSeconds(5),
                    Policy = "ConsecutiveFailures",
                    Path = r.HealthCheckPath,
                },
            },
        };
        return (route, cluster);
    }

    private sealed class Snapshot : IProxyConfig
    {
        private readonly CancellationTokenSource _cts = new();

        public Snapshot(IReadOnlyList<RouteConfig> routes, IReadOnlyList<ClusterConfig> clusters)
        {
            Routes = routes;
            Clusters = clusters;
            ChangeToken = new CancellationChangeToken(_cts.Token);
        }

        public IReadOnlyList<RouteConfig> Routes { get; }
        public IReadOnlyList<ClusterConfig> Clusters { get; }
        public IChangeToken ChangeToken { get; }
        public string RevisionId { get; } = Guid.NewGuid().ToString("N");

        /// <summary>Tells YARP this snapshot is stale so it calls GetConfig again.</summary>
        public void SignalChange() => _cts.Cancel();
    }
}

public sealed class SaveProxyRouteRequest
{
    public string Name { get; set; } = "";
    public string? Description { get; set; }
    public string PathPrefix { get; set; } = "/";
    public string Destinations { get; set; } = "";
    public List<int> Ports { get; set; } = [];
    public ProxyAccess Access { get; set; } = ProxyAccess.SignedIn;
    public bool StripPrefix { get; set; } = true;
    public bool RelaxCsp { get; set; }
    public string LoadBalancing { get; set; } = "PowerOfTwoChoices";
    public string? HealthCheckPath { get; set; }
    public bool Enabled { get; set; } = true;
    public string? Reason { get; set; }
}

public sealed record ConfigProxyRoute(string RouteId, string? Path, string? Ports, string? ClusterId, string? Policy);
public sealed record DestinationHealthInfo(string Destination, string Address, string Health);
public sealed record UpstreamTestResult(string Address, bool Success, string Message, double ElapsedMs);

/// <summary>Admin-only management of UI-defined reverse-proxy routes. Every change is validated, audited and applied live.</summary>
public sealed partial class ProxyRouteService(
    IDbContextFactory<ApplicationDbContext> dbFactory,
    DbProxyConfigProvider provider,
    IConfigValidator validator,
    IProxyStateLookup state,
    EnvironmentRegistry environments,
    AuditService audit,
    IConfiguration configuration,
    IOptions<KeyportOptions> options,
    IHttpClientFactory httpFactory)
{
    public static readonly string[] LoadBalancingPolicies = ["PowerOfTwoChoices", "RoundRobin", "LeastRequests", "Random", "FirstAlphabetical"];

    /// <summary>Top-level path segments owned by Keyport itself; a route may not shadow them.</summary>
    public static readonly HashSet<string> ReservedSegments = new(StringComparer.OrdinalIgnoreCase)
    {
        "api", "admin", "account", "health", "openapi", "ca.crt", "_blazor", "_framework", "_content", "lib", "js", "css", "img",
        "components", "secrets", "secret", "clients", "compare", "users", "certificates", "audit", "activity", "system", "proxy",
        "not-found", "error", "favicon.svg", "app.css",
    };

    [GeneratedRegex(@"^/[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$")]
    private static partial Regex PrefixRegex();

    [GeneratedRegex(@"^[a-z0-9][a-z0-9-]{0,48}$")]
    private static partial Regex NameRegex();

    public async Task<List<ProxyRoute>> ListAsync(UserAccess user)
    {
        RequireAdmin(user);
        await using var db = await dbFactory.CreateDbContextAsync();
        return await db.ProxyRoutes.AsNoTracking().OrderBy(r => r.PathPrefix).ToListAsync();
    }

    /// <summary>Routes defined in appsettings ("ReverseProxy:Routes"), shown read-only in the UI.</summary>
    public List<ConfigProxyRoute> ConfigRoutes() =>
        configuration.GetSection("ReverseProxy:Routes").GetChildren().Select(c => new ConfigProxyRoute(
            c.Key, c["Match:Path"], c["Metadata:Ports"], c["ClusterId"], c["AuthorizationPolicy"])).ToList();

    public async Task<int> CreateAsync(UserAccess user, SaveProxyRouteRequest req, string? ip)
    {
        RequireAdmin(user);
        var entity = new ProxyRoute
        {
            Name = "", PathPrefix = "", Destinations = "", Ports = "",
            CreatedBy = user.UserName, CreatedUtc = DateTime.UtcNow, UpdatedBy = user.UserName, UpdatedUtc = DateTime.UtcNow,
        };
        await using var db = await dbFactory.CreateDbContextAsync();
        await ApplyAndValidateAsync(db, entity, req, isNew: true);
        db.ProxyRoutes.Add(entity);
        await db.SaveChangesAsync();
        provider.Reload();
        await audit.WriteAsync(user.UserName, "proxy.create", AuditResult.Success, target: entity.PathPrefix, clientIp: ip, details: Describe(entity, req.Reason));
        return entity.Id;
    }

    public async Task UpdateAsync(UserAccess user, int id, SaveProxyRouteRequest req, string? ip)
    {
        RequireAdmin(user);
        await using var db = await dbFactory.CreateDbContextAsync();
        var entity = await db.ProxyRoutes.FirstOrDefaultAsync(r => r.Id == id) ?? throw new KeyNotFoundException();
        await ApplyAndValidateAsync(db, entity, req, isNew: false);
        entity.UpdatedBy = user.UserName;
        entity.UpdatedUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
        provider.Reload();
        await audit.WriteAsync(user.UserName, "proxy.update", AuditResult.Success, target: entity.PathPrefix, clientIp: ip, details: Describe(entity, req.Reason));
    }

    public async Task SetEnabledAsync(UserAccess user, int id, bool enabled, string? reason, string? ip)
    {
        RequireAdmin(user);
        RequireReason(reason);
        await using var db = await dbFactory.CreateDbContextAsync();
        var entity = await db.ProxyRoutes.FirstOrDefaultAsync(r => r.Id == id) ?? throw new KeyNotFoundException();
        entity.Enabled = enabled;
        entity.UpdatedBy = user.UserName;
        entity.UpdatedUtc = DateTime.UtcNow;
        await db.SaveChangesAsync();
        provider.Reload();
        await audit.WriteAsync(user.UserName, enabled ? "proxy.enable" : "proxy.disable", AuditResult.Success, target: entity.PathPrefix, clientIp: ip, details: $"reason: {reason}");
    }

    public async Task DeleteAsync(UserAccess user, int id, string? reason, string? ip)
    {
        RequireAdmin(user);
        RequireReason(reason);
        await using var db = await dbFactory.CreateDbContextAsync();
        var entity = await db.ProxyRoutes.FirstOrDefaultAsync(r => r.Id == id) ?? throw new KeyNotFoundException();
        db.ProxyRoutes.Remove(entity);
        await db.SaveChangesAsync();
        provider.Reload();
        await audit.WriteAsync(user.UserName, "proxy.delete", AuditResult.Success, target: entity.PathPrefix, clientIp: ip, details: $"reason: {reason}");
    }

    /// <summary>Live health of each destination, as seen by YARP's active health checks (Unknown if not configured).</summary>
    public List<DestinationHealthInfo> Health(ProxyRoute r)
    {
        if (!r.Enabled || !state.TryGetCluster(DbProxyConfigProvider.IdPrefix + r.Name, out var cluster))
            return [];
        return cluster.Destinations.Values.Select(d => new DestinationHealthInfo(d.DestinationId, d.Model.Config.Address, d.Health.Active.ToString())).ToList();
    }

    public async Task<Dictionary<string, int>> RequestCounts24hAsync(IEnumerable<string> prefixes)
    {
        var since = DateTime.UtcNow.AddDays(-1);
        await using var db = await dbFactory.CreateDbContextAsync();
        var result = new Dictionary<string, int>();
        foreach (var p in prefixes)
            result[p] = await db.ActivityLogs.CountAsync(a => a.TimestampUtc >= since && (a.Path == p || a.Path.StartsWith(p + "/")));
        return result;
    }

    /// <summary>Sends a GET to each destination (plus the health path, if set) from the server. Allow-list rules apply.</summary>
    public async Task<List<UpstreamTestResult>> TestUpstreamsAsync(UserAccess user, SaveProxyRouteRequest req, string? ip)
    {
        RequireAdmin(user);
        var results = new List<UpstreamTestResult>();
        var http = httpFactory.CreateClient("proxy-test");
        foreach (var d in SplitDestinations(req.Destinations))
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var uri = ValidateDestination(d);
                var target = new Uri(uri, string.IsNullOrWhiteSpace(req.HealthCheckPath) ? "" : req.HealthCheckPath.TrimStart('/'));
                using var res = await http.GetAsync(target, HttpCompletionOption.ResponseHeadersRead);
                results.Add(new UpstreamTestResult(target.ToString(), (int)res.StatusCode < 500, $"HTTP {(int)res.StatusCode} {res.ReasonPhrase}", sw.Elapsed.TotalMilliseconds));
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or ValidationException or UriFormatException)
            {
                results.Add(new UpstreamTestResult(d, false, ex.Message.Split('\n')[0], sw.Elapsed.TotalMilliseconds));
            }
        }
        await audit.WriteAsync(user.UserName, "proxy.test-upstream", results.All(r => r.Success) ? AuditResult.Success : AuditResult.Failure,
            target: req.PathPrefix, clientIp: ip, details: string.Join("; ", results.Select(r => $"{r.Address} {r.Message}")));
        return results;
    }

    private async Task ApplyAndValidateAsync(ApplicationDbContext db, ProxyRoute e, SaveProxyRouteRequest req, bool isNew)
    {
        RequireReason(req.Reason);

        var name = req.Name.Trim().ToLowerInvariant();
        if (isNew)
        {
            if (!NameRegex().IsMatch(name)) throw new ValidationException("Name must be 1-49 lowercase letters, digits or '-'.");
            if (await db.ProxyRoutes.AnyAsync(r => r.Name == name)) throw new ValidationException($"A route named '{name}' already exists.");
            e.Name = name;
        }

        var prefix = req.PathPrefix.Trim().TrimEnd('/').ToLowerInvariant();
        if (!PrefixRegex().IsMatch(prefix))
            throw new ValidationException("Path prefix must look like /grafana or /tools/reports (lowercase letters, digits, '.', '_', '-').");
        var first = prefix.Split('/', StringSplitOptions.RemoveEmptyEntries)[0];
        if (ReservedSegments.Contains(first))
            throw new ValidationException($"'/{first}' is used by Keyport itself; choose another prefix.");
        if (await db.ProxyRoutes.AnyAsync(r => r.Id != e.Id && r.PathPrefix == prefix))
            throw new ValidationException($"Another route already uses {prefix}.");
        if (ConfigRoutes().Any(c => c.Path is not null && c.Path.StartsWith(prefix + "/", StringComparison.OrdinalIgnoreCase)))
            throw new ValidationException($"{prefix} is already used by a route defined in configuration.");

        var destinations = SplitDestinations(req.Destinations);
        if (destinations.Count == 0) throw new ValidationException("At least one upstream URL is required.");
        foreach (var d in destinations) ValidateDestination(d);

        var allowedPorts = environments.All.Select(x => x.Port).Append(environments.AdminPort).ToHashSet();
        var ports = req.Ports.Distinct().Order().ToList();
        if (ports.Count == 0) throw new ValidationException("Select at least one port to serve the route on.");
        if (ports.FirstOrDefault(p => !allowedPorts.Contains(p)) is var bad and > 0)
            throw new ValidationException($"Port {bad} is not a Keyport HTTPS listener.");

        if (!LoadBalancingPolicies.Contains(req.LoadBalancing)) throw new ValidationException("Unknown load-balancing policy.");

        var health = string.IsNullOrWhiteSpace(req.HealthCheckPath) ? null : "/" + req.HealthCheckPath.Trim().TrimStart('/');
        if (health is not null && (health.Length > 200 || health.Contains("..") || health.Contains("://")))
            throw new ValidationException("Health check path must be a path such as /healthz.");

        e.Description = string.IsNullOrWhiteSpace(req.Description) ? null : req.Description.Trim();
        e.PathPrefix = prefix;
        e.Destinations = string.Join('\n', destinations);
        e.Ports = string.Join(',', ports);
        e.Access = req.Access;
        e.StripPrefix = req.StripPrefix;
        e.RelaxCsp = req.RelaxCsp;
        e.LoadBalancing = req.LoadBalancing;
        e.HealthCheckPath = health;
        e.Enabled = req.Enabled;

        // Let YARP itself validate the generated config before it can go live.
        var (route, cluster) = DbProxyConfigProvider.ToYarp(e);
        var errors = (await validator.ValidateRouteAsync(route)).Concat(await validator.ValidateClusterAsync(cluster)).ToList();
        if (errors.Count > 0)
            throw new ValidationException("Invalid proxy configuration: " + string.Join(" ", errors.Select(x => x.Message)));
    }

    private static List<string> SplitDestinations(string s) =>
        s.Split(['\n', '\r', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Distinct().ToList();

    /// <summary>Checks scheme, refuses link-local/metadata addresses, and enforces the optional allow-list.</summary>
    public Uri ValidateDestination(string d)
    {
        if (!Uri.TryCreate(d, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            throw new ValidationException($"'{d}' is not an absolute http(s) URL.");
        if (!string.IsNullOrEmpty(uri.UserInfo))
            throw new ValidationException("Upstream URLs must not contain credentials.");

        var host = uri.IdnHost;
        IPAddress.TryParse(host, out var ip);
        if (ip is not null && IsLinkLocal(ip))
            throw new ValidationException($"{host} is a link-local / cloud-metadata address and is never allowed.");
        if (host.Equals("metadata.google.internal", StringComparison.OrdinalIgnoreCase))
            throw new ValidationException("Cloud metadata endpoints are never allowed.");

        var allow = options.Value.Proxy.AllowedUpstreams;
        if (allow.Count > 0 && !allow.Any(a => Matches(a.Trim(), host, ip)))
            throw new ValidationException($"{host} is not in Keyport:Proxy:AllowedUpstreams.");

        return uri.AbsoluteUri.EndsWith('/') ? uri : new Uri(uri.AbsoluteUri + "/");
    }

    private static bool Matches(string entry, string host, IPAddress? ip)
    {
        if (entry.Contains('/'))
            return ip is not null && IPNetwork.TryParse(entry, out var net) && net.Contains(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip);
        if (entry.StartsWith("*.", StringComparison.Ordinal))
            return host.EndsWith(entry[1..], StringComparison.OrdinalIgnoreCase);
        return host.Equals(entry, StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsLinkLocal(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.IsIPv6LinkLocal || IPNetwork.Parse("169.254.0.0/16").Contains(ip) || IPNetwork.Parse("fd00:ec2::/32").Contains(ip);
    }

    private static string Describe(ProxyRoute r, string? reason) =>
        $"{r.PathPrefix} -> {r.Destinations.Replace('\n', ' ')}; ports={r.Ports}; access={r.Access}; strip={r.StripPrefix}; relaxCsp={r.RelaxCsp}; enabled={r.Enabled}; reason: {reason}";

    private static void RequireAdmin(UserAccess a)
    {
        if (!a.IsAdmin) throw new UnauthorizedAccessException("Administrator role required.");
    }

    private static void RequireReason(string? reason)
    {
        if (string.IsNullOrWhiteSpace(reason)) throw new ValidationException("A reason is required for proxy changes.");
    }
}

using System.Collections.Concurrent;
using System.Data.Common;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text.RegularExpressions;
using Keyport.Core.Secrets;
using Keyport.Core.Secrets.Types;
using Keyport.Server.Configuration;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Options;
using Oracle.ManagedDataAccess.Client;

namespace Keyport.Server.Services;

public sealed record ConnectionTestResult(bool Success, string Message, double ElapsedMs);

/// <summary>
/// Tests a secret's settings from the server. The test is chosen by the type definition's <c>Tester</c>:
/// <c>sqlserver</c> / <c>oracle</c> open a real connection (login checked); <c>tcp</c> checks the server is reachable
/// on its host and port (works for any type with a host or URL field; login not checked).
///
/// Because the server makes the connection, every target is checked first (<c>Keyport:ConnectionTest</c>):
/// the host is resolved and EVERY address must be allowed. Link-local / cloud-metadata addresses are always refused;
/// loopback, unspecified addresses and Keyport's own ports are refused unless an allow-list entry names them.
/// Each person is limited to <see cref="ConnectionTestOptions.PerUserPerMinute"/> tests a minute, and failures are
/// reported as a category ("refused", "timed out", "login failed", …) rather than raw driver text.
/// </summary>
public sealed partial class ConnectionTester(IOptions<KeyportOptions> options, TimeProvider time)
{
    public static bool CanTest(SecretType type) => type.Definition.Tester is "sqlserver" or "oracle" or "tcp";

    private readonly ConcurrentDictionary<string, Queue<DateTimeOffset>> _recent = new();

    public async Task<ConnectionTestResult> TestAsync(SecretType type, SecretMetadata meta, SecretPayload payload, string actor, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var def = type.Definition;
        var cfg = options.Value.ConnectionTest;
        if (!cfg.Enabled) return new ConnectionTestResult(false, "Connection tests are turned off on this server.", 0);
        if (!CanTest(type)) return new ConnectionTestResult(false, "This kind of secret can't be tested.", 0);
        if (!TryTakeSlot(actor, cfg.PerUserPerMinute))
            return new ConnectionTestResult(false, "Too many tests in the last minute. Wait a moment and try again.", 0);

        string? target = null;
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));

            var values = SecretFields.Merge(meta, payload);
            var (host, port, cs) = Target(def, type, meta, payload, values);
            if (string.IsNullOrWhiteSpace(host) || port is null)
                return new ConnectionTestResult(false, "Fill in the server name (and port) to test.", 0);
            target = $"{host}:{port}";

            var addresses = await ResolveAllowedAsync(host, port.Value, timeout.Token);
            if (addresses.Error is not null) return new ConnectionTestResult(false, addresses.Error, sw.Elapsed.TotalMilliseconds);

            return def.Tester switch
            {
                "sqlserver" or "oracle" => await TestDriverAsync(def.Tester, cs!, sw, timeout.Token),
                _ => await TestTcpAsync(host, addresses.List[0], port.Value, sw, timeout.Token),
            };
        }
        catch (Exception ex)
        {
            return new ConnectionTestResult(false, Describe(ex, target ?? "the server"), sw.Elapsed.TotalMilliseconds);
        }
    }

    // ---------- where the test would connect ----------

    /// <summary>Host and port the test would reach, taken from what is actually sent (including a full connection string override).</summary>
    private static (string? Host, int? Port, string? ConnectionString) Target(SecretTypeDefinition def, SecretType type, SecretMetadata meta, SecretPayload payload,
        IReadOnlyDictionary<string, string?> values)
    {
        switch (def.Tester)
        {
            case "sqlserver":
            {
                var cs = ConnectionStringFactory.Build(type, meta, payload);
                var ds = new SqlConnectionStringBuilder(cs).DataSource ?? "";
                ds = Regex.Replace(ds, "^(tcp|np|lpc|admin):", "", RegexOptions.IgnoreCase);
                var parts = ds.Split(',', 2);
                var host = parts[0].Split('\\')[0].Trim();
                if (host is "." or "(local)") host = "localhost";
                int? port = parts.Length == 2 && int.TryParse(parts[1].Trim(), out var p) ? p : 1433;
                return (host, port, cs);
            }
            case "oracle":
            {
                var cs = ConnectionStringFactory.Build(type, meta, payload);
                var ds = new OracleConnectionStringBuilder(cs).DataSource ?? "";
                var m = OracleHostRegex().Match(ds);
                if (m.Success)
                {
                    var pm = OraclePortRegex().Match(ds);
                    return (m.Groups[1].Value, pm.Success ? int.Parse(pm.Groups[1].Value) : 1521, cs);
                }
                var ez = EzConnectRegex().Match(ds);
                return ez.Success
                    ? (ez.Groups[1].Value, ez.Groups[2].Success ? int.Parse(ez.Groups[2].Value) : 1521, cs)
                    : (null, null, cs);
            }
            default:
            {
                string? host = values.GetValueOrDefault("host");
                int? port = int.TryParse(values.GetValueOrDefault("port"), out var p) ? p : null;
                if (string.IsNullOrWhiteSpace(host) && values.GetValueOrDefault("url") is { } url && Uri.TryCreate(url, UriKind.Absolute, out var uri))
                {
                    host = uri.Host;
                    port ??= uri.IsDefaultPort && uri.Scheme == "ldaps" ? 636 : uri.IsDefaultPort && uri.Scheme == "ldap" ? 389 : uri.Port > 0 ? uri.Port : null;
                }
                port ??= int.TryParse(def.Field("port")?.Placeholder, out var usual) ? usual : null;
                // SQL Server style "host\instance" isn't reachable as a plain host name.
                return (host?.Split('\\')[0].Trim(), port, null);
            }
        }
    }

    [GeneratedRegex(@"\(\s*HOST\s*=\s*([^)\s]+)\s*\)", RegexOptions.IgnoreCase)]
    private static partial Regex OracleHostRegex();

    [GeneratedRegex(@"\(\s*PORT\s*=\s*(\d+)\s*\)", RegexOptions.IgnoreCase)]
    private static partial Regex OraclePortRegex();

    [GeneratedRegex(@"^(?://)?\[?([^\]:/\s]+)\]?(?::(\d+))?")]
    private static partial Regex EzConnectRegex();

    // ---------- target policy ----------

    private sealed record Resolution(List<IPAddress> List, string? Error);

    private async Task<Resolution> ResolveAllowedAsync(string host, int port, CancellationToken ct)
    {
        var cfg = options.Value.ConnectionTest;
        List<IPAddress> addresses;
        if (IPAddress.TryParse(host.Trim('[', ']'), out var literal)) addresses = [literal];
        else
        {
            try { addresses = [.. await Dns.GetHostAddressesAsync(host, ct)]; }
            catch (SocketException) { return new([], $"The server name '{host}' could not be found from this Keyport server (check the name, and that its DNS/VPN can resolve it)."); }
        }
        if (addresses.Count == 0) return new([], $"The server name '{host}' could not be found from this Keyport server (check the name, and that its DNS/VPN can resolve it).");

        var ownPorts = KeyportPorts();
        foreach (var raw in addresses)
        {
            var ip = raw.IsIPv4MappedToIPv6 ? raw.MapToIPv4() : raw;
            if (IsLinkLocal(ip))
                return new([], "That address is a link-local / cloud-metadata address and can never be tested.");

            var listed = cfg.AllowedTargets.Any(a => Matches(a.Trim(), host, ip));
            if (cfg.AllowedTargets.Count > 0 && !listed)
                return new([], $"{host} is not in the list of servers this Keyport may test (Keyport:ConnectionTest:AllowedTargets).");
            if (!listed && (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)))
                return new([], "Tests to this server's own address are not allowed.");
            if (!listed && ownPorts.Contains(port) && (IPAddress.IsLoopback(ip) || IsLocalAddress(ip)))
                return new([], "Tests to Keyport's own ports are not allowed.");
        }
        return new(addresses, null);
    }

    private HashSet<int> KeyportPorts()
    {
        var o = options.Value;
        return [.. o.Environments.Select(e => e.Port), o.Edge.AdminPort, o.Edge.HttpPort];
    }

    private static bool IsLocalAddress(IPAddress ip)
    {
        try
        {
            return System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .SelectMany(n => n.GetIPProperties().UnicastAddresses).Any(u => u.Address.Equals(ip));
        }
        catch (System.Net.NetworkInformation.NetworkInformationException) { return false; }
    }

    public static bool IsLinkLocal(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        return ip.IsIPv6LinkLocal || IPNetwork.Parse("169.254.0.0/16").Contains(ip) || IPNetwork.Parse("fd00:ec2::/32").Contains(ip);
    }

    private static bool Matches(string entry, string host, IPAddress ip)
    {
        if (entry.Contains('/')) return IPNetwork.TryParse(entry, out var net) && net.Contains(ip);
        if (IPAddress.TryParse(entry, out var single)) return single.Equals(ip);
        if (entry.StartsWith("*.", StringComparison.Ordinal)) return host.EndsWith(entry[1..], StringComparison.OrdinalIgnoreCase);
        return host.Equals(entry, StringComparison.OrdinalIgnoreCase);
    }

    private bool TryTakeSlot(string actor, int perMinute)
    {
        var q = _recent.GetOrAdd(actor, _ => new Queue<DateTimeOffset>());
        lock (q)
        {
            var now = time.GetUtcNow();
            while (q.Count > 0 && now - q.Peek() > TimeSpan.FromMinutes(1)) q.Dequeue();
            if (q.Count >= perMinute) return false;
            q.Enqueue(now);
            return true;
        }
    }

    // ---------- the tests ----------

    private static async Task<ConnectionTestResult> TestDriverAsync(string tester, string cs, Stopwatch sw, CancellationToken ct)
    {
        await using DbConnection conn = tester == "sqlserver"
            ? new SqlConnection(new SqlConnectionStringBuilder(cs) { ConnectTimeout = 8 }.ConnectionString)
            : new OracleConnection(new OracleConnectionStringBuilder(cs) { ConnectionTimeout = 8 }.ConnectionString);
        await conn.OpenAsync(ct);
        return new ConnectionTestResult(true, $"Connected. Server version {conn.ServerVersion}.", sw.Elapsed.TotalMilliseconds);
    }

    /// <summary>Connects to the address that was checked (not the name again), so DNS can't change between check and use.</summary>
    private static async Task<ConnectionTestResult> TestTcpAsync(string host, IPAddress address, int port, Stopwatch sw, CancellationToken ct)
    {
        using var client = new TcpClient(address.AddressFamily);
        await client.ConnectAsync(address, port, ct);
        return new ConnectionTestResult(true, $"The server {host}:{port} is reachable. (This checks the network only, not the login.)", sw.Elapsed.TotalMilliseconds);
    }

    /// <summary>
    /// A plain explanation, never raw driver text (which can echo connection details or fingerprint internal services).
    /// Drivers wrap the real cause (e.g. ORA-50201 "failed to connect" around ORA-50232 "TCP connect failure"), so the
    /// whole exception chain is inspected.
    /// </summary>
    private static string Describe(Exception ex, string target)
    {
        var unreachable = $"Nothing accepted the connection at {target} (refused or blocked). Check the server name and port, " +
            "that the database listener is running, and that this Keyport server can reach it (firewall rules, or a VPN that doesn't carry traffic from containers).";
        var timedOut = $"No answer from {target} within 10 seconds. The address may be firewalled or not routable from this Keyport server (check VPN / network access).";
        var notFound = $"The server name in {target} could not be found from this Keyport server (check the name, and that its DNS/VPN can resolve it).";

        var chain = new List<Exception>();
        for (var e = ex; e is not null; e = e.InnerException) chain.Add(e);

        if (chain.OfType<SocketException>().FirstOrDefault() is { } socket)
            return socket.SocketErrorCode switch
            {
                SocketError.ConnectionRefused or SocketError.ConnectionReset or SocketError.HostUnreachable or SocketError.NetworkUnreachable => unreachable,
                SocketError.HostNotFound or SocketError.NoData or SocketError.TryAgain => notFound,
                SocketError.TimedOut => timedOut,
                _ => unreachable,
            };

        // Oracle: the deepest ORA- code in the chain is the most specific one.
        var ora = chain.Select(e => OraCodeRegex().Match(e.Message)).Where(m => m.Success).Select(m => int.Parse(m.Groups[1].Value)).LastOrDefault();
        if (ora != 0 || chain.Any(e => e is OracleException))
            return ora switch
            {
                1017 or 28000 or 28001 => "The server was reached, but the login failed (wrong user name or password, or the account is locked/expired).",
                12514 or 12505 => $"{target} answered, but it doesn't know that service name / SID.",
                12541 or 12543 or 50232 or 50201 or 12537 => unreachable,
                12170 or 50000 => timedOut,
                12154 or 12545 or 12262 => notFound,
                _ => $"Could not connect to {target} (ORA-{ora:00000}).",
            };

        return ex switch
        {
            OperationCanceledException or TimeoutException => timedOut,
            SqlException { Number: 18456 or 18452 or 18470 or 18486 or 18487 or 18488 } => "The server was reached, but the login failed.",
            SqlException { Number: 4060 } => "The server was reached and the login worked, but the database could not be opened.",
            SqlException { Number: -2 or 258 } => timedOut,
            SqlException { Number: 11001 } => notFound,
            SqlException { Number: 2 or 53 or 40 or 10061 or 10060 or 35 } => unreachable,
            AuthenticationException => "TLS/encryption problem: the server's certificate was not accepted.",
            SqlException s when s.Message.Contains("certificate", StringComparison.OrdinalIgnoreCase) => "TLS/encryption problem: the server's certificate was not accepted.",
            SqlException s => $"Could not connect to {target} (SQL Server error {s.Number}).",
            IOException => unreachable,
            ArgumentException => "The connection settings are not valid.",
            _ => $"Could not connect to {target}.",
        };
    }

    [GeneratedRegex(@"ORA-(\d{4,5})")]
    private static partial Regex OraCodeRegex();
}

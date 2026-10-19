using System.Net;
using System.Net.Sockets;
using Keyport.Server.Configuration;

namespace Keyport.Server.Edge;

/// <summary>
/// Checked when the reverse proxy (and its "Test upstream" button) actually connects, not only when a route is saved:
/// the host name is resolved and every address checked, then the connection goes to a checked address, so a DNS name
/// (or a DNS change after saving) can't point a route at cloud metadata or at this server itself.
///   - link-local / cloud-metadata addresses: always refused;
///   - loopback / unspecified addresses: refused unless <c>Keyport:Proxy:AllowedUpstreams</c> names them;
///   - with an allow-list configured, the address (or host name) must match it.
/// </summary>
public static class UpstreamGuard
{
    public static Func<SocketsHttpConnectionContext, CancellationToken, ValueTask<Stream>> ConnectCallback(Func<ProxyOptions> options) =>
        async (context, ct) =>
        {
            var host = context.DnsEndPoint.Host;
            var addresses = IPAddress.TryParse(host.Trim('[', ']'), out var literal)
                ? [literal]
                : await Dns.GetHostAddressesAsync(host, ct);
            var error = Check(host, addresses, options());
            if (error is not null) throw new HttpRequestException(error);

            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                await socket.ConnectAsync(addresses, context.DnsEndPoint.Port, ct);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        };

    /// <summary>Null when every address may be used; otherwise the reason.</summary>
    public static string? Check(string host, IEnumerable<IPAddress> addresses, ProxyOptions o)
    {
        foreach (var raw in addresses)
        {
            var ip = raw.IsIPv4MappedToIPv6 ? raw.MapToIPv4() : raw;
            if (Services.ConnectionTester.IsLinkLocal(ip))
                return $"{host} resolves to a link-local / cloud-metadata address ({ip}), which is never allowed.";
            var listed = o.AllowedUpstreams.Any(a => Matches(a.Trim(), host, ip));
            if (o.AllowedUpstreams.Count > 0 && !listed)
                return $"{host} ({ip}) is not in Keyport:Proxy:AllowedUpstreams.";
            if (!listed && (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any)))
                return $"{host} resolves to this server's own address ({ip}); add it to Keyport:Proxy:AllowedUpstreams if that is intended.";
        }
        return null;
    }

    public static bool Matches(string entry, string host, IPAddress? ip)
    {
        if (entry.Contains('/'))
            return ip is not null && IPNetwork.TryParse(entry, out var net) && net.Contains(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip);
        if (ip is not null && IPAddress.TryParse(entry, out var single)) return single.Equals(ip);
        if (entry.StartsWith("*.", StringComparison.Ordinal))
            return host.EndsWith(entry[1..], StringComparison.OrdinalIgnoreCase);
        return host.Equals(entry, StringComparison.OrdinalIgnoreCase);
    }
}

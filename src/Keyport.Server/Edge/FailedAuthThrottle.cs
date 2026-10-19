using System.Collections.Concurrent;

namespace Keyport.Server.Edge;

/// <summary>
/// Guards the API against unauthenticated floods. Rate limits are partitioned by key prefix, which a caller can
/// invent freely, so failed authentications are also counted per client IP:
///   - more than <c>Keyport:Edge:FailedAuthPerMinute</c> failures in a minute → the IP gets 429 without any key lookup;
///   - each IP+reason is written to the audit trail at most once a minute (with a count of what was suppressed);
///     every attempt still goes to the activity log.
/// </summary>
public sealed class FailedAuthThrottle(TimeProvider time, Microsoft.Extensions.Options.IOptions<Configuration.KeyportOptions> options)
{
    private int MaxFailuresPerMinute => options.Value.Edge.FailedAuthPerMinute;
    private static readonly TimeSpan Window = TimeSpan.FromMinutes(1);

    private sealed class Counter
    {
        public DateTimeOffset Start;
        public int Failures;
        public readonly Dictionary<string, int> SuppressedByReason = [];
    }

    private readonly ConcurrentDictionary<string, Counter> _byIp = new();

    public bool IsBlocked(string? ip)
    {
        if (ip is null || !_byIp.TryGetValue(ip, out var c)) return false;
        lock (c) return time.GetUtcNow() - c.Start < Window && c.Failures >= MaxFailuresPerMinute;
    }

    /// <summary>Records a failure. Returns whether to audit it now, and how many similar failures were not audited before it.</summary>
    public (bool Audit, int Suppressed) RecordFailure(string? ip, string reason)
    {
        ip ??= "unknown";
        if (_byIp.Count > 10_000) Prune();
        var c = _byIp.GetOrAdd(ip, _ => new Counter { Start = time.GetUtcNow() });
        lock (c)
        {
            var now = time.GetUtcNow();
            int carried = 0;
            if (now - c.Start >= Window)
            {
                carried = c.SuppressedByReason.GetValueOrDefault(reason);
                c.Start = now;
                c.Failures = 0;
                c.SuppressedByReason.Clear();
            }
            c.Failures++;
            if (!c.SuppressedByReason.TryGetValue(reason, out var suppressed))
            {
                c.SuppressedByReason[reason] = 0;
                return (true, carried);
            }
            c.SuppressedByReason[reason] = suppressed + 1;
            return (false, 0);
        }
    }

    private void Prune()
    {
        var cutoff = time.GetUtcNow() - Window;
        foreach (var (ip, c) in _byIp)
            lock (c)
                if (c.Start < cutoff) _byIp.TryRemove(ip, out _);
    }
}

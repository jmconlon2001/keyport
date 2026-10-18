using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Keyport.Core.Audit;

/// <summary>Fields covered by the audit hash chain.</summary>
public interface IAuditRecord
{
    long Id { get; }
    DateTime TimestampUtc { get; }
    string Actor { get; }
    string Action { get; }
    string? Environment { get; }
    string? Target { get; }
    string Result { get; }
    string? ClientIp { get; }
    string? Details { get; }
    string PrevHash { get; }
    string Hash { get; }
}

/// <summary>
/// Tamper-evident audit log: each record's hash covers its own fields and the previous record's hash,
/// so editing or deleting any row breaks every hash after it.
/// </summary>
public static class AuditChain
{
    public const string Genesis = "0000000000000000000000000000000000000000000000000000000000000000";

    public static string ComputeHash(
        string prevHash, long id, DateTime timestampUtc, string actor, string action, string? environment,
        string? target, string result, string? clientIp, string? details)
    {
        var sb = new StringBuilder();
        // Length-prefix every field so values containing the separator can't be shifted between fields.
        foreach (var f in new[]
                 {
                     prevHash, id.ToString(CultureInfo.InvariantCulture), timestampUtc.Ticks.ToString(CultureInfo.InvariantCulture),
                     actor, action, environment ?? "", target ?? "", result, clientIp ?? "", details ?? "",
                 })
        {
            sb.Append(f.Length.ToString(CultureInfo.InvariantCulture)).Append(':').Append(f).Append('|');
        }
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(sb.ToString())));
    }

    public static string ComputeHash(IAuditRecord r) =>
        ComputeHash(r.PrevHash, r.Id, r.TimestampUtc, r.Actor, r.Action, r.Environment, r.Target, r.Result, r.ClientIp, r.Details);

    /// <summary>Verifies records in ascending id order. Returns the id of the first broken record, or null if intact.</summary>
    public static long? FindFirstBreak(IEnumerable<IAuditRecord> orderedRecords, string? expectedPrevHash = null)
    {
        var prev = expectedPrevHash ?? Genesis;
        foreach (var r in orderedRecords)
        {
            if (r.PrevHash != prev || ComputeHash(r) != r.Hash)
                return r.Id;
            prev = r.Hash;
        }
        return null;
    }
}

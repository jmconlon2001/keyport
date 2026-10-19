using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Keyport.Core.Pki;

/// <summary>
/// X.509 Name Constraints (RFC 5280 §4.2.1.10, OID 2.5.29.30), permitted subtrees only. On the root, they limit what
/// clients will accept from this CA to the listed DNS names (each with its subdomains) and IP ranges. Anyone who installs
/// the root then trusts it for those names, not for every website.
/// </summary>
public sealed record NameConstraints(IReadOnlyList<string> DnsNames, IReadOnlyList<IPNetwork> IpRanges)
{
    public const string Oid = "2.5.29.30";

    private static readonly Asn1Tag Permitted = new(TagClass.ContextSpecific, 0, isConstructed: true);
    private static readonly Asn1Tag DnsTag = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag IpTag = new(TagClass.ContextSpecific, 7);

    public X509Extension ToExtension()
    {
        var w = new AsnWriter(AsnEncodingRules.DER);
        using (w.PushSequence())
        using (w.PushSequence(Permitted))
        {
            foreach (var d in DnsNames.Select(n => n.Trim().TrimStart('.').ToLowerInvariant()).Where(n => n.Length > 0).Distinct())
                using (w.PushSequence())
                    w.WriteCharacterString(UniversalTagNumber.IA5String, d, DnsTag);
            foreach (var r in IpRanges.Distinct())
                using (w.PushSequence())
                    w.WriteOctetString([.. r.BaseAddress.GetAddressBytes(), .. Mask(r)], IpTag);
        }
        return new X509Extension(Oid, w.Encode(), critical: true);
    }

    /// <summary>The constraints on a certificate, or null if it has none.</summary>
    public static NameConstraints? Read(X509Certificate2 cert)
    {
        var ext = cert.Extensions.Cast<X509Extension>().FirstOrDefault(e => e.Oid?.Value == Oid);
        if (ext is null) return null;
        var dns = new List<string>();
        var ips = new List<IPNetwork>();
        var outer = new AsnReader(ext.RawData, AsnEncodingRules.DER).ReadSequence();
        if (outer.HasData && outer.PeekTag().HasSameClassAndValue(Permitted))
        {
            var subtrees = outer.ReadSequence(Permitted);
            while (subtrees.HasData)
            {
                var subtree = subtrees.ReadSequence();
                var tag = subtree.PeekTag();
                if (tag.HasSameClassAndValue(DnsTag)) dns.Add(subtree.ReadCharacterString(UniversalTagNumber.IA5String, DnsTag));
                else if (tag.HasSameClassAndValue(IpTag))
                {
                    var bytes = subtree.ReadOctetString(IpTag);
                    var half = bytes.Length / 2;
                    ips.Add(new IPNetwork(new IPAddress(bytes[..half]), bytes[half..].Sum(b => System.Numerics.BitOperations.PopCount(b))));
                }
                else subtree.ReadEncodedValue();
            }
        }
        return new NameConstraints(dns, ips);
    }

    /// <summary>Names that these constraints would NOT allow (empty = all allowed).</summary>
    public IEnumerable<string> Violations(IEnumerable<string> dnsNames, IEnumerable<IPAddress> ips)
    {
        if (DnsNames.Count > 0)
            foreach (var n in dnsNames.Where(n => !DnsNames.Any(c => DnsMatches(c, n))))
                yield return n;
        if (IpRanges.Count > 0)
            foreach (var ip in ips.Where(ip => !IpRanges.Any(r => r.Contains(ip))))
                yield return ip.ToString();
    }

    private static bool DnsMatches(string constraint, string name)
    {
        constraint = constraint.TrimStart('.').ToLowerInvariant();
        name = name.ToLowerInvariant();
        return name == constraint || name.EndsWith("." + constraint, StringComparison.Ordinal);
    }

    private static byte[] Mask(IPNetwork r)
    {
        var mask = new byte[r.BaseAddress.GetAddressBytes().Length];
        for (var i = 0; i < r.PrefixLength; i++) mask[i / 8] |= (byte)(0x80 >> (i % 8));
        return mask;
    }
}

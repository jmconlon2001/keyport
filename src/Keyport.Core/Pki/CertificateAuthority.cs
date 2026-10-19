using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Keyport.Core.Pki;

/// <summary>Minimal internal CA: creates a root and issues TLS server certificates signed by it.</summary>
public static class CertificateAuthority
{
    public static X509Certificate2 CreateRoot(string commonName, TimeSpan lifetime, NameConstraints? constraints = null)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var req = new CertificateRequest(new X500DistinguishedName($"CN={commonName}, O=Keyport Internal CA"), key, HashAlgorithmName.SHA384);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 0, critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, critical: true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));
        if (constraints is not null) req.CertificateExtensions.Add(constraints.ToExtension());

        var now = DateTimeOffset.UtcNow;
        using var cert = req.CreateSelfSigned(now.AddDays(-1), now.Add(lifetime));
        return Reload(cert);
    }

    /// <summary>Issues an ECDSA P-256 server certificate. <paramref name="issuer"/> must include its private key (ECDSA or RSA).</summary>
    public static X509Certificate2 IssueServerCertificate(
        X509Certificate2 issuer, IEnumerable<string> dnsNames, IEnumerable<IPAddress> ipAddresses, TimeSpan lifetime)
    {
        var dns = dnsNames.Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var ips = ipAddresses.Distinct().ToList();
        if (dns.Count == 0 && ips.Count == 0)
            throw new ArgumentException("At least one DNS name or IP address is required.");

        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest(new X500DistinguishedName($"CN={dns.FirstOrDefault() ?? ips[0].ToString()}"), key, HashAlgorithmName.SHA256);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1", "Server Authentication")], critical: false));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, critical: false));
        req.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(issuer, includeKeyIdentifier: true, includeIssuerAndSerial: false));

        var san = new SubjectAlternativeNameBuilder();
        foreach (var n in dns) san.AddDnsName(n);
        foreach (var ip in ips) san.AddIpAddress(ip);
        req.CertificateExtensions.Add(san.Build(critical: false));

        var now = DateTimeOffset.UtcNow;
        var notBefore = now.AddMinutes(-5);
        var notAfter = now.Add(lifetime);
        if (notAfter > issuer.NotAfter) notAfter = issuer.NotAfter;

        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] &= 0x7F; // keep it positive

        X509Certificate2 signed;
        using (var rsa = issuer.GetRSAPrivateKey())
        {
            if (rsa is not null)
            {
                var gen = X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1);
                signed = req.Create(issuer.SubjectName, gen, notBefore, notAfter, serial);
            }
            else
            {
                signed = req.Create(issuer, notBefore, notAfter, serial);
            }
        }

        using (signed)
        using (var withKey = signed.CopyWithPrivateKey(key))
            return Reload(withKey);
    }

    /// <summary>True when the certificate has passed <paramref name="fraction"/> of its validity period.</summary>
    public static bool NeedsRenewal(X509Certificate2 cert, double fraction = 2.0 / 3.0, DateTimeOffset? now = null)
    {
        var t = now ?? DateTimeOffset.UtcNow;
        var total = cert.NotAfter.ToUniversalTime() - cert.NotBefore.ToUniversalTime();
        var renewAt = cert.NotBefore.ToUniversalTime() + total * fraction;
        return t.UtcDateTime >= renewAt;
    }

    public static string Sha256Fingerprint(X509Certificate2 cert) =>
        string.Join(':', Convert.ToHexString(cert.GetCertHash(HashAlgorithmName.SHA256)).Chunk(2).Select(c => new string(c)));

    public static byte[] ExportPrivateKeyPkcs8(X509Certificate2 cert)
    {
        using AsymmetricAlgorithm key = (AsymmetricAlgorithm?)cert.GetECDsaPrivateKey() ?? cert.GetRSAPrivateKey()
            ?? throw new InvalidOperationException("Certificate has no exportable private key.");
        return key.ExportPkcs8PrivateKey();
    }

    /// <summary>Combines a PEM certificate with a PKCS#8 private key (ECDSA or RSA).</summary>
    public static X509Certificate2 FromPemAndPkcs8(string certPem, byte[] pkcs8)
    {
        using var cert = X509Certificate2.CreateFromPem(certPem);
        X509Certificate2 combined;
        if (cert.GetKeyAlgorithm() == "1.2.840.10045.2.1") // id-ecPublicKey
        {
            using var ec = ECDsa.Create();
            ec.ImportPkcs8PrivateKey(pkcs8, out _);
            combined = cert.CopyWithPrivateKey(ec);
        }
        else
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(pkcs8, out _);
            combined = cert.CopyWithPrivateKey(rsa);
        }
        using (combined)
            return Reload(combined);
    }

    /// <summary>
    /// Round-trips through PKCS#12 so the private key is in a form every platform's TLS stack accepts
    /// (ephemeral keys from CopyWithPrivateKey are rejected by SChannel, for example).
    /// </summary>
    private static X509Certificate2 Reload(X509Certificate2 cert) =>
        X509CertificateLoader.LoadPkcs12(cert.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable);
}

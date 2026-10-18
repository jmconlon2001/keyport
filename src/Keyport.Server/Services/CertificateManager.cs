using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Options;
using Keyport.Core.Crypto;
using Keyport.Core.Pki;
using Keyport.Server.Configuration;

namespace Keyport.Server.Services;

/// <summary>
/// Owns the internal CA and the TLS server certificate used by every HTTPS listener.
/// Files under {DataPath}/ca: root.crt (public), root.key.enc (KEK-wrapped), server.crt, server.key.enc.
/// The server certificate is swapped in place, so renewals need no restart.
/// </summary>
public sealed class CertificateManager(
    IOptions<KeyportOptions> options,
    EnvelopeEncryptor encryptor,
    ILogger<CertificateManager> logger)
{
    private const string RootAad = "ca|root";
    private const string ServerAad = "ca|server";
    private readonly Lock _gate = new();
    private X509Certificate2? _issuer;
    private volatile X509Certificate2? _server;

    private string CaDir => Path.Combine(options.Value.DataPath, "ca");
    private string RootCertPath => Path.Combine(CaDir, "root.crt");
    private string RootKeyPath => Path.Combine(CaDir, "root.key.enc");
    private string ServerCertPath => Path.Combine(CaDir, "server.crt");
    private string ServerKeyPath => Path.Combine(CaDir, "server.key.enc");

    /// <summary>The certificate clients must trust (generated root, or the imported enterprise CA).</summary>
    public X509Certificate2 TrustAnchor => _issuer ?? throw new InvalidOperationException("CA not initialized.");

    public X509Certificate2 ServerCertificate => _server ?? throw new InvalidOperationException("CA not initialized.");

    public string TrustAnchorPem => TrustAnchor.ExportCertificatePem();

    public void Initialize()
    {
        lock (_gate)
        {
            Directory.CreateDirectory(CaDir);
            _issuer = LoadOrCreateIssuer();
            logger.LogInformation(
                "Trust anchor: {Subject} valid until {NotAfter:u}. SHA-256 fingerprint: {Fingerprint}. Download from http://<host>:{HttpPort}/ca.crt and verify this fingerprint.",
                _issuer.Subject, _issuer.NotAfter.ToUniversalTime(), CertificateAuthority.Sha256Fingerprint(_issuer), options.Value.Edge.HttpPort);

            var existing = TryLoadServer();
            if (existing is not null && !CertificateAuthority.NeedsRenewal(existing) && SansMatch(existing) && ChainsTo(existing, _issuer))
            {
                _server = existing;
                logger.LogInformation("Loaded server certificate valid until {NotAfter:u}", existing.NotAfter.ToUniversalTime());
            }
            else
            {
                existing?.Dispose();
                IssueServerCertificate("startup");
            }
        }
    }

    /// <summary>Renews the server certificate if it has passed two-thirds of its lifetime. Returns true if renewed.</summary>
    public bool RenewIfDue()
    {
        lock (_gate)
        {
            if (_server is not null && !CertificateAuthority.NeedsRenewal(_server))
                return false;
            IssueServerCertificate("scheduled renewal");
            return true;
        }
    }

    public void ForceRenew()
    {
        lock (_gate) IssueServerCertificate("manual renewal");
    }

    public IReadOnlyList<string> SubjectAlternativeNames
    {
        get
        {
            var ext = ServerCertificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
            if (ext is null) return [];
            return ext.EnumerateDnsNames().Concat(ext.EnumerateIPAddresses().Select(i => i.ToString())).ToList();
        }
    }

    /// <summary>Re-wraps the CA private keys under a new KEK (part of KEK rotation).</summary>
    public void RewrapKeys(MasterKey newKek)
    {
        foreach (var (path, aad) in new[] { (RootKeyPath, RootAad), (ServerKeyPath, ServerAad) })
        {
            if (!File.Exists(path)) continue;
            var blob = ReadBlob(path);
            WriteBlob(path, encryptor.Rewrap(blob, aad, newKek));
        }
    }

    private X509Certificate2 LoadOrCreateIssuer()
    {
        var ca = options.Value.Ca;
        if (!string.IsNullOrWhiteSpace(ca.ImportPfxPath))
        {
            var password = string.IsNullOrWhiteSpace(ca.ImportPfxPasswordFile) ? null : File.ReadAllText(ca.ImportPfxPasswordFile).Trim();
            var imported = X509CertificateLoader.LoadPkcs12FromFile(ca.ImportPfxPath, password, X509KeyStorageFlags.Exportable);
            if (!imported.HasPrivateKey)
                throw new InvalidOperationException($"Imported CA '{ca.ImportPfxPath}' has no private key.");
            if (imported.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault() is not { CertificateAuthority: true })
                throw new InvalidOperationException($"Imported certificate '{imported.Subject}' is not a CA certificate.");
            File.WriteAllText(RootCertPath, imported.ExportCertificatePem());
            logger.LogInformation("Using imported enterprise CA {Subject}", imported.Subject);
            return imported;
        }

        if (File.Exists(RootCertPath) && File.Exists(RootKeyPath))
        {
            var pkcs8 = encryptor.Decrypt(ReadBlob(RootKeyPath), RootAad);
            return CertificateAuthority.FromPemAndPkcs8(File.ReadAllText(RootCertPath), pkcs8);
        }

        logger.LogWarning("No CA found in {CaDir}; generating a new root CA. Distribute root.crt to clients.", CaDir);
        var root = CertificateAuthority.CreateRoot(ca.CommonName, TimeSpan.FromDays(ca.RootLifetimeDays));
        WriteBlob(RootKeyPath, encryptor.Encrypt(CertificateAuthority.ExportPrivateKeyPkcs8(root), RootAad));
        File.WriteAllText(RootCertPath, root.ExportCertificatePem());
        return root;
    }

    private X509Certificate2? TryLoadServer()
    {
        if (!File.Exists(ServerCertPath) || !File.Exists(ServerKeyPath)) return null;
        try
        {
            var pkcs8 = encryptor.Decrypt(ReadBlob(ServerKeyPath), ServerAad);
            return CertificateAuthority.FromPemAndPkcs8(File.ReadAllText(ServerCertPath), pkcs8);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Existing server certificate could not be loaded; a new one will be issued.");
            return null;
        }
    }

    private void IssueServerCertificate(string reason)
    {
        var edge = options.Value.Edge;
        var ips = edge.IpAddresses.Select(s => IPAddress.TryParse(s, out var ip) ? ip : null).OfType<IPAddress>();
        var cert = CertificateAuthority.IssueServerCertificate(
            _issuer!, edge.HostNames, ips, TimeSpan.FromDays(options.Value.Ca.LeafLifetimeDays));

        WriteBlob(ServerKeyPath, encryptor.Encrypt(CertificateAuthority.ExportPrivateKeyPkcs8(cert), ServerAad));
        WriteAtomic(ServerCertPath, cert.ExportCertificatePem());

        // Old certificate is deliberately not disposed: in-flight handshakes may still reference it.
        _server = cert;
        logger.LogInformation("Issued server certificate ({Reason}) for [{Sans}] valid until {NotAfter:u}",
            reason, string.Join(", ", SubjectAlternativeNames), cert.NotAfter.ToUniversalTime());
    }

    private bool SansMatch(X509Certificate2 cert)
    {
        var ext = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (ext is null) return false;
        var have = ext.EnumerateDnsNames().Select(n => n.ToLowerInvariant())
            .Concat(ext.EnumerateIPAddresses().Select(i => i.ToString())).ToHashSet();
        var edge = options.Value.Edge;
        var want = edge.HostNames.Select(n => n.ToLowerInvariant())
            .Concat(edge.IpAddresses.Select(s => IPAddress.TryParse(s, out var ip) ? ip.ToString() : s)).ToHashSet();
        return have.SetEquals(want);
    }

    private static bool ChainsTo(X509Certificate2 leaf, X509Certificate2 issuer) =>
        leaf.IssuerName.RawData.AsSpan().SequenceEqual(issuer.SubjectName.RawData);

    private sealed record BlobFile(string KeyId, string WrappedDek, string Ciphertext);

    private static EncryptedBlob ReadBlob(string path)
    {
        var f = JsonSerializer.Deserialize<BlobFile>(File.ReadAllText(path)) ?? throw new InvalidDataException($"Corrupt key file {path}");
        return new EncryptedBlob(Convert.FromBase64String(f.WrappedDek), Convert.FromBase64String(f.Ciphertext), f.KeyId);
    }

    private static void WriteBlob(string path, EncryptedBlob blob) =>
        WriteAtomic(path, JsonSerializer.Serialize(new BlobFile(blob.KeyId, Convert.ToBase64String(blob.WrappedDek), Convert.ToBase64String(blob.Ciphertext))));

    private static void WriteAtomic(string path, string content)
    {
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, content);
        File.Move(tmp, path, overwrite: true);
    }
}

/// <summary>Checks hourly whether the server certificate needs renewal.</summary>
public sealed class CertificateRenewalService(CertificateManager certs, AuditService audit, JobStatus jobs, ILogger<CertificateRenewalService> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        jobs.Report("certificate-renewal", true, null);
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                if (certs.RenewIfDue())
                    await audit.WriteAsync("system", "certificate.renew", AuditResult.Success, details: "scheduled", ct: stoppingToken);
                jobs.Report("certificate-renewal", true, null);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                logger.LogError(ex, "Server certificate renewal failed; will retry in an hour.");
                jobs.Report("certificate-renewal", false, ex.Message);
            }
        }
    }
}

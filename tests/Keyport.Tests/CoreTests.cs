using Microsoft.Extensions.Configuration;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Data.SqlClient;
using Oracle.ManagedDataAccess.Client;
using Keyport.Core.Audit;
using Keyport.Core.Crypto;
using Keyport.Core.Pki;
using Keyport.Core.Secrets;

namespace Keyport.Tests;

public class EnvelopeEncryptionTests
{
    private static MasterKey NewKey() => new(RandomNumberGenerator.GetBytes(32));

    [Fact]
    public void RoundTrips()
    {
        var enc = new EnvelopeEncryptor(NewKey());
        var blob = enc.EncryptString("p@ss;word=\"x\"", "secret|1|1|1");
        Assert.Equal("p@ss;word=\"x\"", enc.DecryptString(blob, "secret|1|1|1"));
    }

    [Fact]
    public void EachEncryptionUsesFreshDekAndNonce()
    {
        var enc = new EnvelopeEncryptor(NewKey());
        var a = enc.EncryptString("same", "aad");
        var b = enc.EncryptString("same", "aad");
        Assert.NotEqual(a.Ciphertext, b.Ciphertext);
        Assert.NotEqual(a.WrappedDek, b.WrappedDek);
    }

    [Fact]
    public void TamperedCiphertextFails()
    {
        var enc = new EnvelopeEncryptor(NewKey());
        var blob = enc.EncryptString("value", "aad");
        blob.Ciphertext[^1] ^= 0x01;
        Assert.ThrowsAny<CryptographicException>(() => enc.Decrypt(blob, "aad"));
    }

    [Fact]
    public void CiphertextMovedToAnotherEnvironmentFails()
    {
        var enc = new EnvelopeEncryptor(NewKey());
        var blob = enc.EncryptString("prod-password", "secret|7|4|1"); // env 4
        Assert.ThrowsAny<CryptographicException>(() => enc.Decrypt(blob, "secret|7|1|1")); // replayed as env 1
    }

    [Fact]
    public void WrongMasterKeyFails()
    {
        var blob = new EnvelopeEncryptor(NewKey()).EncryptString("value", "aad");
        Assert.ThrowsAny<CryptographicException>(() => new EnvelopeEncryptor(NewKey()).Decrypt(blob, "aad"));
    }

    [Fact]
    public void RewrapMovesToNewKekWithoutChangingCiphertext()
    {
        var oldKey = NewKey();
        var newKey = NewKey();
        var blob = new EnvelopeEncryptor(oldKey).EncryptString("value", "aad");
        var rewrapped = new EnvelopeEncryptor(oldKey).Rewrap(blob, "aad", newKey);

        Assert.Equal(blob.Ciphertext, rewrapped.Ciphertext);
        Assert.Equal(newKey.KeyId, rewrapped.KeyId);
        Assert.Equal("value", new EnvelopeEncryptor(newKey).DecryptString(rewrapped, "aad"));
        Assert.ThrowsAny<CryptographicException>(() => new EnvelopeEncryptor(oldKey).Decrypt(rewrapped, "aad"));
    }

    [Theory]
    [InlineData("base64")]
    [InlineData("hex")]
    [InlineData("raw")]
    public void MasterKeyLoadsSupportedFormats(string format)
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        var path = Path.GetTempFileName();
        try
        {
            switch (format)
            {
                case "base64": File.WriteAllText(path, Convert.ToBase64String(bytes) + "\n"); break;
                case "hex": File.WriteAllText(path, Convert.ToHexString(bytes)); break;
                default: File.WriteAllBytes(path, bytes); break;
            }
            Assert.Equal(new MasterKey(bytes).KeyId, MasterKey.LoadFromFile(path).KeyId);
        }
        finally
        {
            File.Delete(path);
        }
    }

    [Fact]
    public void MasterKeyRejectsWrongLength()
    {
        var path = Path.GetTempFileName();
        File.WriteAllText(path, Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)));
        try { Assert.Throws<InvalidDataException>(() => MasterKey.LoadFromFile(path)); }
        finally { File.Delete(path); }
    }
}

public class ApiKeyTests
{
    [Fact]
    public void GeneratedKeyVerifiesAndParses()
    {
        var k = ApiKeys.Generate();
        Assert.True(ApiKeys.TryParsePrefix(k.Plaintext, out var prefix));
        Assert.Equal(k.Prefix, prefix);
        Assert.True(ApiKeys.Verify(k.Plaintext, k.Hash));
        Assert.False(ApiKeys.Verify(k.Plaintext + "x", k.Hash));
        Assert.DoesNotContain(k.Plaintext, k.Hash);
    }

    [Theory]
    [InlineData("")]
    [InlineData("Bearer")]
    [InlineData("sm_short_abc")]
    [InlineData("xx_abcdefgh_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void RejectsMalformedKeys(string key) => Assert.False(ApiKeys.TryParsePrefix(key, out _));

    [Fact]
    public void GeneratedPasswordsAreStrongAndConnectionStringSafe()
    {
        for (var i = 0; i < 200; i++)
        {
            var p = PasswordGenerator.Generate(24);
            Assert.Equal(24, p.Length);
            Assert.Contains(p, char.IsUpper);
            Assert.Contains(p, char.IsLower);
            Assert.Contains(p, char.IsDigit);
            Assert.DoesNotContain(p, c => c is ';' or '=' or '\'' or '"' or ' ' or '{' or '}');
        }
    }
}

public class SecretNameTests
{
    [Theory]
    [InlineData("billing/oracle-main", true)]
    [InlineData("a", true)]
    [InlineData("Billing/x", false)]
    [InlineData("/leading", false)]
    [InlineData("trailing/", false)]
    [InlineData("a//b", false)]
    [InlineData("../etc/passwd", false)]
    public void ValidatesNames(string name, bool valid) => Assert.Equal(valid, SecretNames.IsValid(name));

    [Theory]
    [InlineData("billing/oracle-main", "billing/*", true)]
    [InlineData("billing/eu/sql", "billing/*", true)]
    [InlineData("billingx/sql", "billing/*", false)]
    [InlineData("billing", "billing/*", false)]
    [InlineData("hr/sql", "billing/sql", false)]
    [InlineData("hr/sql", "hr/sql", true)]
    [InlineData("anything/at/all", "*", true)]
    public void MatchesGrants(string name, string pattern, bool expected) => Assert.Equal(expected, SecretNames.MatchesGrant(name, pattern));
}

public class ConnectionStringTests
{
    [Fact]
    public void SqlServerEscapesHostilePasswords()
    {
        var meta = new SecretMetadata { Host = "sql01.corp", Port = 1433, Database = "Billing", Encrypt = "Mandatory" };
        var payload = new SecretPayload { Username = "svc_billing", Password = "a;b=c'd\"e" };
        var cs = ConnectionStringFactory.Build(SecretType.SqlServerConnection, meta, payload);

        var parsed = new SqlConnectionStringBuilder(cs);
        Assert.Equal("sql01.corp,1433", parsed.DataSource);
        Assert.Equal("Billing", parsed.InitialCatalog);
        Assert.Equal("svc_billing", parsed.UserID);
        Assert.Equal("a;b=c'd\"e", parsed.Password);
        Assert.Equal(SqlConnectionEncryptOption.Mandatory, parsed.Encrypt);
    }

    [Fact]
    public void SqlServerIntegratedSecurityOmitsCredentials()
    {
        var cs = ConnectionStringFactory.Build(SecretType.SqlServerConnection,
            new SecretMetadata { Host = "sql01", IntegratedSecurity = true }, new SecretPayload { Username = "x", Password = "y" });
        var parsed = new SqlConnectionStringBuilder(cs);
        Assert.True(parsed.IntegratedSecurity);
        Assert.Equal("", parsed.Password);
    }

    [Fact]
    public void OracleEzConnectAndDescriptor()
    {
        var payload = new SecretPayload { Username = "app", Password = "p;w" };
        var ez = new OracleConnectionStringBuilder(ConnectionStringFactory.Build(SecretType.OracleConnection,
            new SecretMetadata { Host = "ora01", Port = 1522, ServiceName = "ORCLPDB1" }, payload));
        Assert.Equal("ora01:1522/ORCLPDB1", ez.DataSource);
        Assert.Equal("p;w", ez.Password);

        var sid = new OracleConnectionStringBuilder(ConnectionStringFactory.Build(SecretType.OracleConnection,
            new SecretMetadata { Host = "ora01", Sid = "LEGACY" }, payload));
        Assert.Contains("(SID=LEGACY)", sid.DataSource);
        Assert.Contains("(PORT=1521)", sid.DataSource);
    }

    [Fact]
    public void ExtraOptionsArePassedThrough()
    {
        var cs = ConnectionStringFactory.Build(SecretType.SqlServerConnection,
            new SecretMetadata { Host = "s", ExtraOptions = "MultipleActiveResultSets=True;Connect Timeout=45" }, new SecretPayload { Username = "u", Password = "p" });
        var parsed = new SqlConnectionStringBuilder(cs);
        Assert.True(parsed.MultipleActiveResultSets);
        Assert.Equal(45, parsed.ConnectTimeout);
    }

    [Fact]
    public void MaskedPreviewNeverContainsPassword()
    {
        var meta = new SecretMetadata { Host = "s", Database = "d" };
        var masked = ConnectionStringFactory.BuildMasked(SecretType.SqlServerConnection, meta, new SecretPayload { Username = "u", Password = "TopSecret1!" });
        Assert.DoesNotContain("TopSecret1!", masked);
        Assert.Contains(ConnectionStringFactory.Mask, masked);

        var overrideMasked = ConnectionStringFactory.BuildMasked(SecretType.SqlServerConnection, meta,
            new SecretPayload { ConnectionStringOverride = "Server=x;User Id=u;Password=TopSecret1!" });
        Assert.DoesNotContain("TopSecret1!", overrideMasked);
    }
}

public class AuditChainTests
{
    private sealed record Rec(long Id, DateTime TimestampUtc, string Actor, string Action, string? Environment, string? Target,
        string Result, string? ClientIp, string? Details, string PrevHash, string Hash) : IAuditRecord;

    private static List<Rec> Chain(int n)
    {
        var list = new List<Rec>();
        var prev = AuditChain.Genesis;
        for (var i = 1; i <= n; i++)
        {
            var ts = new DateTime(2026, 1, 1, 0, 0, i, DateTimeKind.Utc);
            var h = AuditChain.ComputeHash(prev, i, ts, "alice", "secret.reveal", "Prod", $"s{i}", "Success", "10.0.0.1", null);
            list.Add(new Rec(i, ts, "alice", "secret.reveal", "Prod", $"s{i}", "Success", "10.0.0.1", null, prev, h));
            prev = h;
        }
        return list;
    }

    [Fact]
    public void IntactChainVerifies() => Assert.Null(AuditChain.FindFirstBreak(Chain(20)));

    [Fact]
    public void EditedRowIsDetected()
    {
        var c = Chain(20);
        c[7] = c[7] with { Actor = "mallory" };
        Assert.Equal(8, AuditChain.FindFirstBreak(c));
    }

    [Fact]
    public void DeletedRowIsDetected()
    {
        var c = Chain(20);
        c.RemoveAt(10);
        Assert.Equal(12, AuditChain.FindFirstBreak(c));
    }

    [Fact]
    public void FieldBoundaryShiftChangesHash()
    {
        var ts = DateTime.UtcNow;
        Assert.NotEqual(
            AuditChain.ComputeHash(AuditChain.Genesis, 1, ts, "ab", "c", null, null, "Success", null, null),
            AuditChain.ComputeHash(AuditChain.Genesis, 1, ts, "a", "bc", null, null, "Success", null, null));
    }
}

public class CertificateAuthorityTests
{
    [Fact]
    public void IssuesServerCertificateChainingToRoot()
    {
        using var root = CertificateAuthority.CreateRoot("Test Root", TimeSpan.FromDays(365));
        using var leaf = CertificateAuthority.IssueServerCertificate(root, ["localhost", "secrets.corp.local"], [IPAddress.Loopback], TimeSpan.FromDays(90));

        Assert.True(leaf.HasPrivateKey);
        var san = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>().Single();
        Assert.Contains("secrets.corp.local", san.EnumerateDnsNames());
        Assert.Contains(IPAddress.Loopback, san.EnumerateIPAddresses());

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        Assert.True(chain.Build(leaf), string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation)));
        Assert.Contains(leaf.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages.Cast<Oid>(), o => o.Value == "1.3.6.1.5.5.7.3.1");
    }

    [Fact]
    public void LeafNeverOutlivesIssuer()
    {
        using var root = CertificateAuthority.CreateRoot("Short Root", TimeSpan.FromDays(30));
        using var leaf = CertificateAuthority.IssueServerCertificate(root, ["localhost"], [], TimeSpan.FromDays(90));
        Assert.True(leaf.NotAfter <= root.NotAfter);
    }

    [Fact]
    public void RenewalThresholdIsTwoThirds()
    {
        using var root = CertificateAuthority.CreateRoot("R", TimeSpan.FromDays(365));
        using var leaf = CertificateAuthority.IssueServerCertificate(root, ["localhost"], [], TimeSpan.FromDays(90));
        var start = leaf.NotBefore.ToUniversalTime();
        Assert.False(CertificateAuthority.NeedsRenewal(leaf, now: start.AddDays(50)));
        Assert.True(CertificateAuthority.NeedsRenewal(leaf, now: start.AddDays(61)));
    }

    [Fact]
    public void PemAndEncryptedKeyRoundTrip()
    {
        using var root = CertificateAuthority.CreateRoot("R", TimeSpan.FromDays(365));
        var restored = CertificateAuthority.FromPemAndPkcs8(root.ExportCertificatePem(), CertificateAuthority.ExportPrivateKeyPkcs8(root));
        Assert.True(restored.HasPrivateKey);
        Assert.Equal(root.Thumbprint, restored.Thumbprint);
    }
}

public class GrantOptionTests
{
    [Fact]
    public void BuildsAllFoldersAndSecretsWithCounts()
    {
        var opts = Keyport.Server.Services.ApiClientService.BuildGrantOptions([
            ("billing/eu/sql", SecretType.SqlServerConnection),
            ("billing/oracle", SecretType.OracleConnection),
            ("shared/smtp", SecretType.BasicAuth),
        ]);
        var map = opts.ToDictionary(o => o.Pattern, o => o.SecretCount);

        Assert.Equal(3, map["*"]);
        Assert.Equal(2, map["billing/*"]);
        Assert.Equal(1, map["billing/eu/*"]);
        Assert.Equal(1, map["shared/*"]);
        Assert.Equal(1, map["billing/oracle"]);
        Assert.DoesNotContain("billing/oracle/*", map.Keys);
        Assert.Equal("*", opts[0].Pattern);
    }

    [Fact]
    public void NoSecretsMeansNoOptions() =>
        Assert.Empty(Keyport.Server.Services.ApiClientService.BuildGrantOptions([]));
}

public class GrantOptionOrderTests
{
    [Fact]
    public void OptionsAreInTreeOrder()
    {
        var order = Keyport.Server.Services.ApiClientService.BuildGrantOptions([
            ("shared/smtp", SecretType.BasicAuth),
            ("billing/sql-main", SecretType.SqlServerConnection),
            ("billing/eu/sql-replica", SecretType.SqlServerConnection),
            ("standalone", SecretType.Generic),
        ]).Select(o => o.Pattern).ToList();

        Assert.Equal(["*", "billing/*", "billing/eu/*", "billing/eu/sql-replica", "billing/sql-main", "shared/*", "shared/smtp", "standalone"], order);
    }
}

public class KeyAgeTests
{
    [Theory]
    [InlineData(0, "less than a day old")]
    [InlineData(1, "1 day old")]
    [InlineData(10, "10 days old")]
    [InlineData(21, "3 weeks old")]
    [InlineData(95, "3 months old")]
    [InlineData(365 + 70, "1 year 2 months old")]
    [InlineData(730, "2 years old")]
    public void AgeIsHumanFriendly(int daysAgo, string expected) =>
        Assert.Equal(expected, Keyport.Server.Components.Shared.AppPageBase.Age(DateTime.UtcNow.AddDays(-daysAgo).AddMinutes(-1)));

    [Fact]
    public void KeysOverAYearAreFlagged()
    {
        Assert.False(Keyport.Server.Components.Shared.AppPageBase.IsOldKey(DateTime.UtcNow.AddDays(-300)));
        Assert.True(Keyport.Server.Components.Shared.AppPageBase.IsOldKey(DateTime.UtcNow.AddDays(-400)));
    }
}

public class RenameCompatibilityTests
{
    [Fact]
    public void NewKeysUseKpSchemeAndLegacySmKeysStillParse()
    {
        var k = ApiKeys.Generate();
        Assert.StartsWith("kp_", k.Plaintext);

        // A key issued before the rename (sm_ scheme) must still be accepted.
        var legacy = "sm_abcdefgh_" + new string('A', 43);
        Assert.True(ApiKeys.TryParsePrefix(legacy, out var prefix));
        Assert.Equal("abcdefgh", prefix);
        Assert.True(ApiKeys.Verify(legacy, ApiKeys.Hash(legacy)));
        Assert.False(ApiKeys.TryParsePrefix("xx_abcdefgh_" + new string('A', 43), out _));
    }

    [Fact]
    public void LegacySettingsSectionIsMappedToKeyport()
    {
        var cfg = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["SecretManager:Edge:AdminPort"] = "18443",
            ["SecretManager:Environments:0:Name"] = "Dev",
        }).Build();
        var map = Keyport.Server.Configuration.KeyportOptions.LegacyOverrides(cfg);
        Assert.Equal("18443", map["Keyport:Edge:AdminPort"]);
        Assert.Equal("Dev", map["Keyport:Environments:0:Name"]);
    }
}

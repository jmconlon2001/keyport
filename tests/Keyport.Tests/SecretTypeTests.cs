using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Keyport.Core.Secrets;
using Keyport.Core.Secrets.Types;

namespace Keyport.Tests;

public class SecretTypeTests
{
    private const string Hostile = "p;w=d'\" @/%#: x&?+";

    private static readonly SecretTypeRegistry Registry = SecretTypeRegistry.CreateDefault();

    private static Dictionary<string, string?> V(params (string Key, string? Value)[] values) =>
        values.ToDictionary(v => v.Key, v => v.Value, StringComparer.OrdinalIgnoreCase);

    private static string Render(string type, string output, Dictionary<string, string?> values)
    {
        var d = Registry.Get(type);
        return Registry.Render(d, d.Outputs.Single(o => o.Key == output), values);
    }

    // ---------- renderers ----------

    [Fact]
    public void KeyValueRendererEscapesHostileValues()
    {
        var cs = Render("PostgresConnection", OutputKeys.ConnectionString,
            V(("host", "pg-01"), ("database", "billing"), ("username", "app"), ("password", Hostile), ("sslMode", "Require"), ("extraOptions", "Pooling=true")));
        var b = new System.Data.Common.DbConnectionStringBuilder { ConnectionString = cs };
        Assert.Equal(Hostile, b["Password"]);
        Assert.Equal("pg-01", b["Host"]);
        Assert.Equal("true", b["Pooling"]);
        Assert.False(b.ContainsKey("Port"));   // blank fields are left out, not rendered empty
    }

    [Fact]
    public void UriRendererPercentEncodesCredentialsAndPath()
    {
        var url = Render("RabbitMqConnection", OutputKeys.ConnectionString,
            V(("host", "mq-01"), ("port", "5671"), ("virtualHost", "/prod"), ("tls", "true"), ("username", "a@b"), ("password", Hostile)));
        Assert.StartsWith("amqps://", url);
        var uri = new Uri(url);
        Assert.Equal("mq-01", uri.Host);
        Assert.Equal(5671, uri.Port);
        var userInfo = uri.UserInfo.Split(':');
        Assert.Equal("a@b", Uri.UnescapeDataString(userInfo[0]));
        Assert.Equal(Hostile, Uri.UnescapeDataString(userInfo[1]));
        Assert.Equal("/prod", Uri.UnescapeDataString(uri.AbsolutePath.TrimStart('/')));
    }

    [Fact]
    public void UriRendererUsesPlainSchemeWithoutTls()
    {
        var url = Render("RabbitMqConnection", OutputKeys.ConnectionString, V(("host", "mq-01"), ("username", "u"), ("password", "p")));
        Assert.StartsWith("amqp://u:p@mq-01", url);
    }

    [Fact]
    public void TemplateRendererQuotesValuesInsideJaasConfig()
    {
        var props = Render("KafkaSasl", "properties",
            V(("bootstrapServers", "k1:9093"), ("securityProtocol", "SASL_SSL"), ("saslMechanism", "PLAIN"),
              ("loginModule", "org.apache.kafka.common.security.plain.PlainLoginModule"), ("username", "svc"), ("password", "a\"b\\c")));
        Assert.Contains("bootstrap.servers=k1:9093", props);
        Assert.Contains("password=\"a\\\"b\\\\c\";", props);
    }

    [Fact]
    public void TemplateEncodersApply()
    {
        var def = new SecretTypeDefinition
        {
            Key = "Enc", Title = "Enc", Category = Categories.Other,
            Fields = [new() { Key = "v", Label = "V", Sensitive = true }],
            Outputs = [new() { Key = "o", Label = "O", Renderer = "template",
                Settings = new Dictionary<string, string> { ["template"] = "{{v|url}} {{v|json}} {{v|base64}} {{v}}" } }],
        };
        var reg = SecretTypeRegistry.Create([def]);
        var o = reg.Render(def, def.Outputs[0], V(("v", "a b\"&")));
        Assert.Equal($"a%20b%22%26 a b\\u0022\\u0026 {Convert.ToBase64String(Encoding.UTF8.GetBytes("a b\"&"))} a b\"&", o);
    }

    [Fact]
    public void ConnectionStringOverrideWinsAndIsMaskedInPreview()
    {
        var d = Registry.Get("SqlServerConnection");
        var values = V(("host", "sql01"), ("username", "u"), ("password", "real"), ("connectionStringOverride", "Server=x;User ID=u;Password=Secret-123"));
        Assert.Equal("Server=x;User ID=u;Password=Secret-123", Registry.RenderAll(d, values)[OutputKeys.ConnectionString]);
        var masked = Registry.RenderMasked(d, values)[OutputKeys.ConnectionString];
        Assert.DoesNotContain("Secret-123", masked);
    }

    [Fact]
    public void UrlPreviewShowsPlainMask()
    {
        var d = Registry.Get("PostgresConnection");
        var masked = Registry.RenderMasked(d, V(("host", "pg"), ("database", "db"), ("username", "u"), ("password", "secret")));
        Assert.Equal("postgresql://u:********@pg/db", masked["url"]);
    }

    [Fact]
    public void MaskedPreviewNeverShowsSensitiveValues()
    {
        foreach (var d in Registry.All)
        {
            var values = d.Fields.ToDictionary(f => f.Key, f => (string?)(f.Kind switch
            {
                FieldKind.Bool => "true",
                FieldKind.Port or FieldKind.Number => "1234",
                FieldKind.Select => f.Options[0],
                FieldKind.Url => "https://h.example/x",
                _ => f.Sensitive ? "SENSITIVE-" + f.Key : "clear" + f.Key,
            }), StringComparer.OrdinalIgnoreCase);
            foreach (var (_, text) in Registry.RenderMasked(d, values))
                foreach (var f in d.SensitiveFields.Where(f => !f.CopyOnPromote))
                    Assert.DoesNotContain("SENSITIVE-" + f.Key, text);
        }
    }

    // ---------- PEM ----------

    private static (string Cert, string Key) MakeCert(string cn)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var req = new CertificateRequest($"CN={cn}", key, HashAlgorithmName.SHA256);
        using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        return (cert.ExportCertificatePem(), key.ExportPkcs8PrivateKeyPem());
    }

    [Fact]
    public void TlsCertificateWithMatchingKeyIsAcceptedAndBundled()
    {
        var (cert, key) = MakeCert("api.corp.local");
        var d = Registry.Get("TlsCertificate");
        var values = V(("certificate", cert), ("privateKey", key));
        Assert.Empty(Registry.Validate(d, values));
        var outputs = Registry.RenderAll(d, values);
        Assert.Contains("BEGIN CERTIFICATE", outputs["pem"]);
        Assert.Contains("PRIVATE KEY", outputs["pem"]);
        Assert.DoesNotContain("PRIVATE KEY", outputs["fullchain"]);
    }

    [Fact]
    public void TlsCertificateWithWrongKeyIsRejected()
    {
        var (cert, _) = MakeCert("api.corp.local");
        var (_, otherKey) = MakeCert("other");
        var d = Registry.Get("TlsCertificate");
        Assert.NotEmpty(Registry.Validate(d, V(("certificate", cert), ("privateKey", otherKey))));
        Assert.NotEmpty(Registry.Validate(d, V(("certificate", "not a pem"), ("privateKey", otherKey))));
    }

    // ---------- field rules ----------

    [Fact]
    public void RequiredAndPatternRulesAreChecked()
    {
        var aws = Registry.Get("AwsAccessKey");
        Assert.NotEmpty(Registry.Validate(aws, V(("accessKeyId", "nope"), ("secretAccessKey", "s"))));
        Assert.Empty(Registry.Validate(aws, V(("accessKeyId", "AKIAABCDEFGHIJKLMNOP"), ("secretAccessKey", "s"))));
        Assert.NotEmpty(Registry.Validate(aws, V(("accessKeyId", "AKIAABCDEFGHIJKLMNOP"))));
    }

    [Fact]
    public void RequireOneOfAcceptsEitherField()
    {
        var oracle = Registry.Get("OracleConnection");
        var baseValues = V(("host", "ora"), ("username", "u"), ("password", "p"));
        Assert.NotEmpty(Registry.Missing(oracle, baseValues, includeSensitive: true));
        Assert.Empty(Registry.Missing(oracle, new Dictionary<string, string?>(baseValues) { ["sid"] = "ORCL" }, includeSensitive: true));
        Assert.Empty(Registry.Missing(oracle, new Dictionary<string, string?>(baseValues) { ["serviceName"] = "BILL" }, includeSensitive: true));
    }

    [Fact]
    public void IntegratedSecurityTurnsOffSqlLogin()
    {
        var sql = Registry.Get("SqlServerConnection");
        var values = V(("host", "sql01"), ("integratedSecurity", "true"));
        Assert.Empty(Registry.Missing(sql, values, includeSensitive: true));
        Assert.False(SecretTypeRegistry.IsActive(sql.Field("password")!, values));
    }

    [Fact]
    public void PromotionCopiesOnlyFieldsMarkedForCopy()
    {
        var sftp = Registry.Get("SftpLogin");
        var clear = new SecretMetadata { Host = "sftp.corp" };
        var sensitive = new SecretPayload { Username = "drop", Password = "pw" };
        sensitive["privateKey"] = "-----BEGIN OPENSSH PRIVATE KEY-----";
        var (c, s) = SecretTypeRegistry.ForPromotion(sftp, clear, sensitive);
        Assert.Equal("sftp.corp", c.Host);
        Assert.Equal("drop", s.Username);
        Assert.Null(s.Password);
        Assert.Null(s["privateKey"]);
    }

    [Fact]
    public void LegacyJsonWithNumbersAndBoolsStillLoads()
    {
        var m = SecretMetadata.FromJson("""{"host":"sql01","port":1433,"encrypt":"Mandatory","trustServerCertificate":true,"description":"old row"}""");
        Assert.Equal("sql01", m.Host);
        Assert.Equal(1433, m.Port);
        Assert.True(m.TrustServerCertificate);
        Assert.Equal("old row", m.Description);
    }

    [Fact]
    public void OriginalConnectionStringsAreUnchanged()
    {
        // Pinned output for the original types, so stored secrets keep serving identical strings.
        var sql = ConnectionStringFactory.Build(SecretType.SqlServerConnection,
            new SecretMetadata { Host = "sql01", Port = 1433, Database = "Billing", Encrypt = "Mandatory", ApplicationName = "billing-api" },
            new SecretPayload { Username = "svc", Password = "pw;1" });
        Assert.Equal("Data Source=sql01,1433;Initial Catalog=Billing;User ID=svc;Password=\"pw;1\";Encrypt=True;Application Name=billing-api", sql);

        var ora = ConnectionStringFactory.Build(SecretType.OracleConnection,
            new SecretMetadata { Host = "ora01", Port = 1521, ServiceName = "BILL" },
            new SecretPayload { Username = "app", Password = "pw" });
        Assert.Equal("USER ID=app;PASSWORD=pw;DATA SOURCE=ora01:1521/BILL", ora);
    }

    // ---------- registry validation ----------

    private static SecretTypeDefinition Valid(Action<SecretTypeDefinition>? change = null)
    {
        var d = new SecretTypeDefinition
        {
            Key = "Thing", Title = "Thing", Category = Categories.Other,
            Fields = [new() { Key = "url", Label = "Address" }, new() { Key = "token", Label = "Token", Sensitive = true }],
            Outputs = [new() { Key = "o", Label = "O", Renderer = "template", Settings = new Dictionary<string, string> { ["template"] = "{{url}}" } }],
        };
        change?.Invoke(d);
        return d;
    }

    [Fact]
    public void ValidCustomDefinitionRegisters() => Assert.NotNull(SecretTypeRegistry.Create([Valid()]).Find("thing"));

    public static TheoryData<string, Action<SecretTypeDefinition>> BadDefinitions => new()
    {
        { "Invalid type key", d => d.Key = "has space" },
        { "needs a Title", d => d.Title = "" },
        { "unknown category", d => d.Category = "toys" },
        { "invalid field key", d => d.Fields[0].Key = "Bad-Key" },
        { "is reserved", d => d.Fields[0].Key = "description" },
        { "defined twice", d => d.Fields[1].Key = "url" },
        { "needs Options", d => d.Fields[0].Kind = FieldKind.Select },
        { "invalid Pattern", d => d.Fields[0].Pattern = "([" },
        { "unknown field 'nope'", d => d.Fields[0].DisabledWhen = "nope" },
        { "unknown renderer", d => d.Outputs[0].Renderer = "xml" },
        { "unknown field", d => d.Outputs[0].Settings = new Dictionary<string, string> { ["template"] = "{{missing}}" } },
    };

    [Theory, MemberData(nameof(BadDefinitions))]
    public void InvalidDefinitionsAreRejectedWithClearMessage(string expected, Action<SecretTypeDefinition> change)
    {
        var ex = Assert.Throws<SecretTypeDefinitionException>(() => SecretTypeRegistry.Create([Valid(change)]));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public void DuplicateTypeKeysAreRejected()
    {
        var ex = Assert.Throws<SecretTypeDefinitionException>(() => SecretTypeRegistry.Create([.. BuiltInTypes.All, Valid(d => d.Key = "sqlserverconnection")]));
        Assert.Contains("more than once", ex.Message);
    }

    [Fact]
    public void UnknownTypeLoadsAsReadOnlyPlaceholder()
    {
        var d = Registry.Get("RetiredType");
        Assert.True(d.IsUnknown);
        Assert.Empty(d.Outputs);
    }
}

public class SecretTypeLoaderTests
{
    [Fact]
    public void DocumentedSampleTypeLoads()
    {
        var root = Path.Combine(Path.GetTempPath(), "kp-types-" + Guid.NewGuid().ToString("N")[..8]);
        var dir = Path.Combine(root, Keyport.Server.Services.SecretTypeLoader.FolderName);
        Directory.CreateDirectory(dir);
        try
        {
            var repo = AppContext.BaseDirectory;
            while (!File.Exists(Path.Combine(repo, "Keyport.sln"))) repo = Path.GetDirectoryName(repo)!;
            File.Copy(Path.Combine(repo, "docs", "secret-types", "elasticsearch.json"), Path.Combine(dir, "elasticsearch.json"));

            var reg = Keyport.Server.Services.SecretTypeLoader.Load(new Keyport.Server.Configuration.KeyportOptions { DataPath = root });
            var d = reg.Find("Elasticsearch")!;
            Assert.Equal("file: elasticsearch.json", d.Source);
            Assert.Equal("ApiKey abc==", reg.RenderAll(d, new Dictionary<string, string?> { ["url"] = "https://es:9200", ["apiKey"] = "abc==" })["authorizationHeader"]);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void BrokenTypeFileStopsStartupWithFileName()
    {
        var root = Path.Combine(Path.GetTempPath(), "kp-types-" + Guid.NewGuid().ToString("N")[..8]);
        var dir = Path.Combine(root, Keyport.Server.Services.SecretTypeLoader.FolderName);
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "bad.json"), """{ "key": "Bad", "title": "Bad", "category": "other", "outputs": [ { "key": "o", "label": "O", "renderer": "nope" } ] }""");
            var ex = Assert.Throws<SecretTypeDefinitionException>(() =>
                Keyport.Server.Services.SecretTypeLoader.Load(new Keyport.Server.Configuration.KeyportOptions { DataPath = root }));
            Assert.Contains("bad.json", ex.Message);
        }
        finally { Directory.Delete(root, true); }
    }
}

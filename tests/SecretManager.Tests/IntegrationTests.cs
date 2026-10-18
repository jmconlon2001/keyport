using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecretManager.Core.Crypto;
using SecretManager.Core.Secrets;
using SecretManager.Server;
using SecretManager.Server.Data;
using SecretManager.Server.Services;

namespace SecretManager.Tests;

/// <summary>Runs the real server (Kestrel, TLS, all listeners) on random ports with a throwaway data directory.</summary>
public sealed class ServerFixture : IAsyncLifetime
{
    public static readonly string[] EnvNames = ["Dev", "Test", "Upgrade", "Prod"];

    public string DataDir { get; } = Path.Combine(Path.GetTempPath(), "sm-test-" + Guid.NewGuid().ToString("N")[..8]);
    public string KeyFile => Path.Combine(DataDir, "master.key");
    public int HttpPort { get; private set; }
    public int AdminPort { get; private set; }
    public Dictionary<string, int> EnvPorts { get; } = [];
    public WebApplication App { get; private set; } = null!;
    public X509Certificate2 Ca { get; private set; } = null!;
    public UserAccess Admin { get; } = new("test-admin-id", "test-admin", true, false, new Dictionary<int, EnvironmentRole>());

    public EnvironmentRegistry Environments => App.Services.GetRequiredService<EnvironmentRegistry>();
    public SecretService Secrets => App.Services.GetRequiredService<SecretService>();
    public ApiClientService Clients => App.Services.GetRequiredService<ApiClientService>();
    public AuditService Audit => App.Services.GetRequiredService<AuditService>();
    public EnvironmentInfo Env(string name) => Environments.ByName(name)!;

    public string[] Args()
    {
        var args = new List<string>
        {
            $"--SecretManager:DataPath={DataDir}",
            $"--SecretManager:MasterKeyFile={KeyFile}",
            $"--SecretManager:Edge:HttpPort={HttpPort}",
            $"--SecretManager:Edge:AdminPort={AdminPort}",
            "--SecretManager:Edge:BindAddress=127.0.0.1",
            "--SecretManager:Edge:HostNames:0=localhost",
            "--SecretManager:Edge:IpAddresses:0=127.0.0.1",
            "--SecretManager:Logs:ApiLogRetentionDays=30",
            "--SecretManager:Logs:UiLogRetentionDays=30",
            "--SecretManager:Logs:AuditRetentionDays=0",
            "--SecretManager:Proxy:AllowedUpstreams:0=127.0.0.1/32",
            "--SecretManager:Proxy:AllowedUpstreams:1=localhost",
            "--Logging:LogLevel:Default=Warning",
        };
        for (var i = 0; i < EnvNames.Length; i++)
        {
            args.Add($"--SecretManager:Environments:{i}:Name={EnvNames[i]}");
            args.Add($"--SecretManager:Environments:{i}:Port={EnvPorts[EnvNames[i]]}");
            args.Add($"--SecretManager:Environments:{i}:Protected={(EnvNames[i] is "Upgrade" or "Prod")}");
        }
        return [.. args];
    }

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(DataDir);
        await File.WriteAllTextAsync(KeyFile, MasterKey.GenerateBase64());
        HttpPort = FreePort();
        AdminPort = FreePort();
        foreach (var n in EnvNames) EnvPorts[n] = FreePort();

        App = SecretManagerApp.Build(Args());
        await SecretManagerApp.InitializeAsync(App);
        await App.StartAsync();
        Ca = App.Services.GetRequiredService<CertificateManager>().TrustAnchor;
    }

    /// <summary>Stops the server and starts a fresh process-equivalent instance on the same data directory and ports.</summary>
    public async Task RestartAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        App = SecretManagerApp.Build(Args());
        await SecretManagerApp.InitializeAsync(App);
        await App.StartAsync();
        Ca = App.Services.GetRequiredService<CertificateManager>().TrustAnchor;
    }

    public async Task DisposeAsync()
    {
        await App.StopAsync();
        await App.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        try { Directory.Delete(DataDir, recursive: true); } catch (IOException) { }
    }

    /// <summary>HttpClient that trusts only the server's internal CA (no validation bypass).</summary>
    public HttpClient Client(string? apiKey = null)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            SslOptions =
            {
                CertificateChainPolicy = new X509ChainPolicy
                {
                    TrustMode = X509ChainTrustMode.CustomRootTrust,
                    CustomTrustStore = { Ca },
                    RevocationMode = X509RevocationMode.NoCheck,
                },
            },
        };
        var c = new HttpClient(handler);
        if (apiKey is not null) c.DefaultRequestHeaders.Authorization = new("Bearer", apiKey);
        return c;
    }

    public string Url(string env, string path) => $"https://localhost:{EnvPorts[env]}{path}";
    public string AdminUrl(string path) => $"https://localhost:{AdminPort}{path}";

    public async Task<ApplicationDbContext> DbAsync() =>
        await App.Services.GetRequiredService<IDbContextFactory<ApplicationDbContext>>().CreateDbContextAsync();

    private static int FreePort()
    {
        using var l = new TcpListener(IPAddress.Loopback, 0);
        l.Start();
        return ((IPEndPoint)l.LocalEndpoint).Port;
    }
}

[CollectionDefinition("server")]
public class ServerCollection : ICollectionFixture<ServerFixture>;

[Collection("server")]
public class ApiIntegrationTests(ServerFixture f)
{
    private async Task<int> CreateSqlSecretAsync(string env, string name, string password)
    {
        var e = f.Env(env);
        return await f.Secrets.CreateAsync(f.Admin, e.Id, new SaveSecretRequest
        {
            Name = name,
            Type = SecretType.SqlServerConnection,
            Metadata = new SecretMetadata { Host = $"sql-{env.ToLowerInvariant()}.corp", Port = 1433, Database = "Billing" },
            Payload = new SecretPayload { Username = $"svc_{env.ToLowerInvariant()}", Password = password },
            Reason = e.Protected ? "test" : null,
        }, "127.0.0.1");
    }

    private async Task<string> CreateClientAsync(string env, string grants)
    {
        var e = f.Env(env);
        var (_, key) = await f.Clients.CreateAsync(f.Admin, e.Id,
            new SaveApiClientRequest { Name = $"app-{Guid.NewGuid():N}"[..20], Grants = grants, Reason = e.Protected ? "test" : null }, "127.0.0.1");
        return key;
    }

    [Fact]
    public async Task ClientReadsConnectionStringOnItsOwnEnvironmentPort()
    {
        await CreateSqlSecretAsync("Dev", "billing/sql-main", "Dev-Pass;1=");
        var key = await CreateClientAsync("Dev", "billing/*");

        using var http = f.Client(key);
        var res = await http.GetAsync(f.Url("Dev", "/api/v1/connections/billing/sql-main"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("no-store", res.Headers.CacheControl?.ToString());

        var body = await res.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Dev", body.GetProperty("environment").GetString());
        var cs = new Microsoft.Data.SqlClient.SqlConnectionStringBuilder(body.GetProperty("connectionString").GetString());
        Assert.Equal("Dev-Pass;1=", cs.Password);
        Assert.Equal("svc_dev", body.GetProperty("components").GetProperty("username").GetString());
    }

    [Fact]
    public async Task EveryKeyIsRejectedOnEveryOtherEnvironmentPort()
    {
        var keys = new Dictionary<string, string>();
        foreach (var env in ServerFixture.EnvNames)
        {
            await CreateSqlSecretAsync(env, "matrix/sql", $"{env}-pw-123!");
            keys[env] = await CreateClientAsync(env, "matrix/*");
        }

        foreach (var keyEnv in ServerFixture.EnvNames)
        foreach (var portEnv in ServerFixture.EnvNames)
        {
            using var http = f.Client(keys[keyEnv]);
            var res = await http.GetAsync(f.Url(portEnv, "/api/v1/credentials/matrix/sql"));
            if (keyEnv == portEnv)
            {
                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
                var body = await res.Content.ReadFromJsonAsync<JsonElement>();
                Assert.Equal($"{keyEnv}-pw-123!", body.GetProperty("password").GetString());
            }
            else
            {
                Assert.True(res.StatusCode == HttpStatusCode.Unauthorized, $"{keyEnv} key on {portEnv} port returned {res.StatusCode}");
                Assert.DoesNotContain("pw-123", await res.Content.ReadAsStringAsync());
            }
        }

        var (denied, _) = await f.Audit.QueryAsync(new AuditQuery(Action: "api.authenticate", Result: AuditResult.Denied, Take: 100));
        Assert.Contains(denied, a => a.Details!.Contains("presented on Prod port"));
    }

    [Fact]
    public async Task UngrantedAndMissingSecretsLookIdentical()
    {
        await CreateSqlSecretAsync("Test", "hr/sql", "Hr-Pass-1!");
        await CreateSqlSecretAsync("Test", "billing/sql", "Bill-Pass-1!");
        var key = await CreateClientAsync("Test", "billing/*");
        using var http = f.Client(key);

        var ungranted = await http.GetAsync(f.Url("Test", "/api/v1/secrets/hr/sql"));
        var missing = await http.GetAsync(f.Url("Test", "/api/v1/secrets/billing/does-not-exist"));
        Assert.Equal(HttpStatusCode.NotFound, ungranted.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Equal(await missing.Content.ReadAsStringAsync(), await ungranted.Content.ReadAsStringAsync());
    }

    [Fact]
    public async Task ListOnlyShowsGrantedNamesWithoutValues()
    {
        await CreateSqlSecretAsync("Dev", "list/a", "List-A-pw1!");
        await CreateSqlSecretAsync("Dev", "other/b", "Other-B-pw1!");
        var key = await CreateClientAsync("Dev", "list/*");
        using var http = f.Client(key);

        var body = await http.GetStringAsync(f.Url("Dev", "/api/v1/secrets"));
        Assert.Contains("list/a", body);
        Assert.DoesNotContain("other/b", body);
        Assert.DoesNotContain("pw1", body);
    }

    [Fact]
    public async Task DisabledExpiredAndCidrRestrictedKeysAreRejected()
    {
        await CreateSqlSecretAsync("Dev", "lim/sql", "Lim-pw-12345!");
        var e = f.Env("Dev");

        var (disabled, k1) = await f.Clients.CreateAsync(f.Admin, e.Id, new SaveApiClientRequest { Name = "disabled-app", Grants = "*" }, null);
        await f.Clients.SetDisabledAsync(f.Admin, disabled.Id, true, null, null);
        var (_, k2) = await f.Clients.CreateAsync(f.Admin, e.Id, new SaveApiClientRequest { Name = "expired-app", Grants = "*", ExpiresUtc = DateTime.UtcNow.AddMinutes(-1) }, null);
        var (_, k3) = await f.Clients.CreateAsync(f.Admin, e.Id, new SaveApiClientRequest { Name = "cidr-app", Grants = "*", AllowedCidrs = "10.99.0.0/16" }, null);
        var (_, k4) = await f.Clients.CreateAsync(f.Admin, e.Id, new SaveApiClientRequest { Name = "loopback-app", Grants = "*", AllowedCidrs = "127.0.0.0/8" }, null);

        foreach (var k in new[] { k1, k2, k3 })
        {
            using var http = f.Client(k);
            Assert.Equal(HttpStatusCode.Unauthorized, (await http.GetAsync(f.Url("Dev", "/api/v1/secrets/lim/sql"))).StatusCode);
        }
        using var ok = f.Client(k4);
        Assert.Equal(HttpStatusCode.OK, (await ok.GetAsync(f.Url("Dev", "/api/v1/secrets/lim/sql"))).StatusCode);
    }

    [Fact]
    public async Task GrantsMustReferToExistingSecretsOrFolders()
    {
        await CreateSqlSecretAsync("Test", "grants/eu/sql", "Grants-pw-1!");
        var test = f.Env("Test");
        Task Create(string grants) => f.Clients.CreateAsync(f.Admin, test.Id,
            new SaveApiClientRequest { Name = $"g-{Guid.NewGuid():N}"[..20], Grants = grants }, null);

        await Create("grants/eu/sql");   // exact secret
        await Create("grants/*");        // folder
        await Create("grants/eu/*");     // nested folder
        await Create("*");               // all (environment has secrets)

        var ex = await Assert.ThrowsAsync<ValidationException>(() => Create("grants/eu/typo"));
        Assert.Contains("not found: grants/eu/typo", ex.Message);
        await Assert.ThrowsAsync<ValidationException>(() => Create("nothing-here/*"));
        await Assert.ThrowsAsync<ValidationException>(() => Create("grants/eu/sql/*")); // a secret is not a folder
    }

    [Fact]
    public async Task ExistingGrantsSurviveSecretDeletionOnEdit()
    {
        var dev = f.Env("Dev");
        var secretId = await CreateSqlSecretAsync("Dev", "stale/sql", "Stale-pw-1!");
        await CreateSqlSecretAsync("Dev", "stale2/sql", "Stale2-pw-1!");
        var (client, _) = await f.Clients.CreateAsync(f.Admin, dev.Id, new SaveApiClientRequest { Name = "stale-app", Grants = "stale/sql" }, null);
        await f.Secrets.DeleteAsync(f.Admin, secretId, null, null);

        // Editing keeps the now-stale grant and may add an existing one, but cannot add a new unknown one.
        await f.Clients.UpdateAsync(f.Admin, client.Id, new SaveApiClientRequest { Grants = "stale/sql\nstale2/sql" }, null);
        await Assert.ThrowsAsync<ValidationException>(() =>
            f.Clients.UpdateAsync(f.Admin, client.Id, new SaveApiClientRequest { Grants = "stale/sql\nnew-unknown" }, null));
    }

    [Fact]
    public async Task CreatingClientWithoutExpiryNeverExpires()
    {
        await CreateSqlSecretAsync("Dev", "noexp/sql", "NoExp-pw-1!");
        var before = DateTime.UtcNow.AddSeconds(-1);
        var (client, key) = await f.Clients.CreateAsync(f.Admin, f.Env("Dev").Id, new SaveApiClientRequest { Name = "no-expiry-app", Grants = "noexp/*" }, null);

        Assert.Null(client.ExpiresUtc);
        Assert.True(client.KeyCreatedUtc >= before, "key issue date recorded on creation");
        using var http = f.Client(key);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(f.Url("Dev", "/api/v1/secrets/noexp/sql"))).StatusCode);

        var status = await http.GetFromJsonAsync<JsonElement>(f.Url("Dev", "/api/v1/status"));
        Assert.Equal(JsonValueKind.Null, status.GetProperty("keyExpiresUtc").ValueKind);
        Assert.True(status.GetProperty("keyIssuedUtc").GetDateTime() >= before);
    }

    [Fact]
    public async Task RotatingAnExpiredKeyClearsTheExpiryAndResetsKeyAge()
    {
        await CreateSqlSecretAsync("Dev", "expired/sql", "Expired-pw-1!");
        var dev = f.Env("Dev");
        var (client, oldKey) = await f.Clients.CreateAsync(f.Admin, dev.Id,
            new SaveApiClientRequest { Name = "rotate-expired-app", Grants = "expired/*", ExpiresUtc = DateTime.UtcNow.AddMinutes(-1) }, null);
        using (var old = f.Client(oldKey))
            Assert.Equal(HttpStatusCode.Unauthorized, (await old.GetAsync(f.Url("Dev", "/api/v1/secrets/expired/sql"))).StatusCode);

        // Pretend the key was issued long ago, then rotate.
        await using (var db = await f.DbAsync())
        {
            var row = await db.ApiClients.SingleAsync(c => c.Id == client.Id);
            row.KeyCreatedUtc = DateTime.UtcNow.AddYears(-2);
            await db.SaveChangesAsync();
        }
        var newKey = await f.Clients.RotateKeyAsync(f.Admin, client.Id, null, null);

        using var http = f.Client(newKey);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(f.Url("Dev", "/api/v1/secrets/expired/sql"))).StatusCode);
        await using (var db = await f.DbAsync())
        {
            var row = await db.ApiClients.SingleAsync(c => c.Id == client.Id);
            Assert.Null(row.ExpiresUtc);
            Assert.True(row.KeyCreatedUtc > DateTime.UtcNow.AddMinutes(-1), "key age resets on rotation");
        }
        var (events, _) = await f.Audit.QueryAsync(new AuditQuery(Action: "client.rotate-key", Target: "rotate-expired-app"));
        Assert.Contains(events, e => e.Details!.Contains("expired date cleared"));
    }

    [Fact]
    public async Task RotatingKeepsFutureExpiry()
    {
        await CreateSqlSecretAsync("Dev", "future/sql", "Future-pw-1!");
        var expiry = DateTime.UtcNow.AddDays(30);
        var (client, _) = await f.Clients.CreateAsync(f.Admin, f.Env("Dev").Id,
            new SaveApiClientRequest { Name = "future-app", Grants = "future/*", ExpiresUtc = expiry }, null);
        await f.Clients.RotateKeyAsync(f.Admin, client.Id, null, null);
        await using var db = await f.DbAsync();
        var row = await db.ApiClients.SingleAsync(c => c.Id == client.Id);
        Assert.NotNull(row.ExpiresUtc);
        Assert.True(Math.Abs((row.ExpiresUtc!.Value - expiry).TotalSeconds) < 1);
    }

    [Fact]
    public async Task RotatedKeyInvalidatesOldKey()
    {
        await CreateSqlSecretAsync("Dev", "rot/sql", "Rot-pw-12345!");
        var e = f.Env("Dev");
        var (client, oldKey) = await f.Clients.CreateAsync(f.Admin, e.Id, new SaveApiClientRequest { Name = "rotating-app", Grants = "rot/*" }, null);
        var newKey = await f.Clients.RotateKeyAsync(f.Admin, client.Id, null, null);

        using var oldHttp = f.Client(oldKey);
        using var newHttp = f.Client(newKey);
        Assert.Equal(HttpStatusCode.Unauthorized, (await oldHttp.GetAsync(f.Url("Dev", "/api/v1/secrets/rot/sql"))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await newHttp.GetAsync(f.Url("Dev", "/api/v1/secrets/rot/sql"))).StatusCode);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/Account/Login")]
    [InlineData("/admin/api/status")]
    [InlineData("/openapi/v1.json")]
    [InlineData("/ca.crt")]
    public async Task UiAndAdminRoutesDoNotExistOnEnvironmentPorts(string path)
    {
        using var http = f.Client();
        foreach (var env in ServerFixture.EnvNames)
            Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync(f.Url(env, path))).StatusCode);
    }

    [Fact]
    public async Task SecretsApiDoesNotExistOnAdminPort()
    {
        await CreateSqlSecretAsync("Dev", "admin-port/sql", "Admin-port-pw1!");
        var key = await CreateClientAsync("Dev", "*");
        using var http = f.Client(key);
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync(f.AdminUrl("/api/v1/secrets/admin-port/sql"))).StatusCode);
    }

    [Theory]
    [InlineData("/admin/api/status")]
    [InlineData("/admin/api/audit")]
    [InlineData("/openapi/v1.json")]
    public async Task AdminApiRequiresSignInAndAnswersWithStatusCodes(string path)
    {
        using var http = f.Client();
        Assert.Equal(HttpStatusCode.Unauthorized, (await http.GetAsync(f.AdminUrl(path))).StatusCode);
    }

    [Fact]
    public async Task UiPagesRedirectToLoginWhenSignedOut()
    {
        using var http = f.Client();
        var res = await http.GetAsync(f.AdminUrl("/secrets"));
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Contains("/Account/Login", res.Headers.Location!.ToString());
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(f.AdminUrl("/Account/Login"))).StatusCode);
    }

    [Fact]
    public async Task HttpPortServesOnlyBootstrapEndpoints()
    {
        using var http = f.Client();
        var ca = await http.GetStringAsync($"http://localhost:{f.HttpPort}/ca.crt");
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", ca);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync($"http://localhost:{f.HttpPort}/health/live")).StatusCode);

        var redirect = await http.GetAsync($"http://localhost:{f.HttpPort}/secrets");
        Assert.Equal(HttpStatusCode.Redirect, redirect.StatusCode);
        Assert.Equal($"https://localhost:{f.AdminPort}/secrets", redirect.Headers.Location!.ToString());

        // Secrets are never served over plain HTTP.
        Assert.Equal(HttpStatusCode.Redirect, (await http.GetAsync($"http://localhost:{f.HttpPort}/api/v1/secrets")).StatusCode);
    }

    [Fact]
    public async Task HealthEndpointsRespondOnEveryPort()
    {
        using var http = f.Client();
        foreach (var url in ServerFixture.EnvNames.Select(e => f.Url(e, "/health")).Append(f.AdminUrl("/health")))
        {
            var json = await http.GetFromJsonAsync<JsonElement>(url);
            Assert.Equal("Healthy", json.GetProperty("status").GetString());
            var names = json.GetProperty("checks").EnumerateArray().Select(c => c.GetProperty("name").GetString()).ToList();
            Assert.Contains("database", names);
            Assert.Contains("master-key", names);
            Assert.Contains("certificates", names);
        }
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(f.Url("Prod", "/health/ready"))).StatusCode);
    }

    [Fact]
    public async Task ClientStatusEndpointDescribesCaller()
    {
        await CreateSqlSecretAsync("Upgrade", "status/sql", "Status-pw-1!");
        var key = await CreateClientAsync("Upgrade", "status/*");
        using var http = f.Client(key);
        var json = await http.GetFromJsonAsync<JsonElement>(f.Url("Upgrade", "/api/v1/status"));
        Assert.Equal("Upgrade", json.GetProperty("environment").GetString());
        Assert.Equal("Healthy", json.GetProperty("health").GetString());
        Assert.Contains("status/*", json.GetProperty("grants").EnumerateArray().Select(g => g.GetString()));
    }

    [Fact]
    public async Task EveryApiRequestIsWrittenToTheActivityLog()
    {
        await CreateSqlSecretAsync("Test", "act/sql", "Act-pw-12345!");
        var key = await CreateClientAsync("Test", "act/*");
        using var http = f.Client(key);
        await http.GetAsync(f.Url("Test", "/api/v1/connections/act/sql"));
        await http.GetAsync(f.Url("Test", "/api/v1/connections/act/missing"));
        using var anon = f.Client("sm_zzzzzzzz_notarealkeynotarealkeynotarealkeynotarea");
        await anon.GetAsync(f.Url("Test", "/api/v1/connections/act/sql"));

        var logger = f.App.Services.GetRequiredService<ActivityLogger>();
        List<ActivityLog> items = [];
        for (var i = 0; i < 40 && items.Count < 3; i++)
        {
            await Task.Delay(100);
            items = (await logger.QueryAsync(new ActivityQuery(Source: LogSource.Api, Path: "act/", Take: 50))).Items;
        }
        Assert.Contains(items, a => a.StatusCode == 200 && a.Target == "act/sql" && a.Environment == "Test" && a.DurationMs > 0);
        Assert.Contains(items, a => a.StatusCode == 404 && a.Target == "act/missing");
        Assert.Contains(items, a => a.StatusCode == 401 && a.Actor == "key:zzzzzzzz");
    }

    [Fact]
    public async Task RateLimitReturns429()
    {
        // Uses a dedicated instance-wide limit: 300/min per key by default. Fire past it with one key.
        await CreateSqlSecretAsync("Dev", "rl/sql", "Rl-pw-12345!");
        var key = await CreateClientAsync("Dev", "rl/*");
        using var http = f.Client(key);
        var codes = new List<HttpStatusCode>();
        for (var i = 0; i < 320; i++)
            codes.Add((await http.GetAsync(f.Url("Dev", "/api/v1/status"))).StatusCode);
        Assert.Contains(HttpStatusCode.TooManyRequests, codes);
    }
}

[Collection("server")]
public class SecretServiceTests(ServerFixture f)
{
    [Fact]
    public async Task ProtectedEnvironmentsRequireReason()
    {
        var prod = f.Env("Prod");
        var req = new SaveSecretRequest
        {
            Name = "noreason/sql",
            Type = SecretType.BasicAuth,
            Payload = new SecretPayload { Username = "u", Password = "Pw-123456789!" },
        };
        await Assert.ThrowsAsync<ValidationException>(() => f.Secrets.CreateAsync(f.Admin, prod.Id, req, null));

        req.Reason = "CHG-1";
        var id = await f.Secrets.CreateAsync(f.Admin, prod.Id, req, null);
        await Assert.ThrowsAsync<ValidationException>(() => f.Secrets.RevealAsync(f.Admin, id, null, null));
        Assert.Equal("Pw-123456789!", (await f.Secrets.RevealAsync(f.Admin, id, "incident 42", null)).Password);

        var (audit, _) = await f.Audit.QueryAsync(new AuditQuery(Action: "secret.reveal", Target: "noreason/sql"));
        Assert.Contains(audit, a => a.Details!.Contains("incident 42"));
    }

    [Fact]
    public async Task PromotionCopiesSettingsButNotPassword()
    {
        var test = f.Env("Test");
        var upgrade = f.Env("Upgrade");
        var id = await f.Secrets.CreateAsync(f.Admin, test.Id, new SaveSecretRequest
        {
            Name = "promo/oracle",
            Type = SecretType.OracleConnection,
            Metadata = new SecretMetadata { Host = "ora-test", Port = 1521, ServiceName = "BILL" },
            Payload = new SecretPayload { Username = "bill_app", Password = "Test-Only-Pw-1!" },
        }, null);

        var draft = await f.Secrets.PreparePromotionAsync(f.Admin, id, upgrade.Id, null);
        Assert.Equal("promo/oracle", draft.Name);
        Assert.Equal("BILL", draft.Metadata.ServiceName);
        Assert.Equal("bill_app", draft.Payload!.Username);
        Assert.Null(draft.Payload.Password);
        Assert.Null(draft.Payload.ConnectionStringOverride);
    }

    [Fact]
    public async Task VersionsAndRollbackNeverRewriteHistory()
    {
        var dev = f.Env("Dev");
        var id = await f.Secrets.CreateAsync(f.Admin, dev.Id, new SaveSecretRequest
        {
            Name = "ver/basic",
            Type = SecretType.BasicAuth,
            Payload = new SecretPayload { Username = "u", Password = "Version-One-1!" },
        }, null);
        await f.Secrets.UpdateAsync(f.Admin, id, new SaveSecretRequest { Payload = new SecretPayload { Username = "u", Password = "Version-Two-2!" } }, null);
        await f.Secrets.RollbackAsync(f.Admin, id, 1, null, null);

        var detail = await f.Secrets.GetAsync(f.Admin, id);
        Assert.Equal(3, detail!.CurrentVersion);
        Assert.Equal("Version-One-1!", (await f.Secrets.RevealAsync(f.Admin, id, null, null)).Password);
        Assert.Equal("Version-Two-2!", (await f.Secrets.RevealAsync(f.Admin, id, null, null, version: 2)).Password);
    }

    [Fact]
    public async Task EnvironmentScopedUsersCannotCrossEnvironments()
    {
        var dev = f.Env("Dev");
        var prod = f.Env("Prod");
        var id = await f.Secrets.CreateAsync(f.Admin, prod.Id, new SaveSecretRequest
        {
            Name = "scoped/prod",
            Type = SecretType.Generic,
            Payload = new SecretPayload { Value = "prod-only" },
            Reason = "test",
        }, null);

        var devEditor = new UserAccess("u1", "dev-editor", false, false, new Dictionary<int, EnvironmentRole> { [dev.Id] = EnvironmentRole.Editor });
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => f.Secrets.RevealAsync(devEditor, id, "x", null));
        Assert.Null(await f.Secrets.GetAsync(devEditor, id));
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => f.Secrets.ListAsync(devEditor, prod.Id));

        var prodViewer = new UserAccess("u2", "prod-viewer", false, false, new Dictionary<int, EnvironmentRole> { [prod.Id] = EnvironmentRole.Viewer });
        Assert.Equal("prod-only", (await f.Secrets.RevealAsync(prodViewer, id, "x", null)).Value);
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => f.Secrets.DeleteAsync(prodViewer, id, "x", null));

        var (denied, _) = await f.Audit.QueryAsync(new AuditQuery(Actor: "dev-editor", Result: AuditResult.Denied));
        Assert.NotEmpty(denied);
    }

    [Fact]
    public async Task InvalidConnectionSettingsAreRejected()
    {
        var dev = f.Env("Dev");
        await Assert.ThrowsAsync<ValidationException>(() => f.Secrets.CreateAsync(f.Admin, dev.Id, new SaveSecretRequest
        {
            Name = "bad/oracle",
            Type = SecretType.OracleConnection,
            Metadata = new SecretMetadata { Host = "ora" },
            Payload = new SecretPayload { Username = "u", Password = "p" },
        }, null));
        await Assert.ThrowsAsync<ValidationException>(() => f.Secrets.CreateAsync(f.Admin, dev.Id, new SaveSecretRequest
        {
            Name = "Bad Name",
            Type = SecretType.Generic,
            Payload = new SecretPayload { Value = "v" },
        }, null));
    }

    [Fact]
    public async Task CiphertextIsBoundToItsRow()
    {
        var dev = f.Env("Dev");
        var a = await f.Secrets.CreateAsync(f.Admin, dev.Id, new SaveSecretRequest { Name = "bind/a", Type = SecretType.Generic, Payload = new SecretPayload { Value = "A" } }, null);
        var b = await f.Secrets.CreateAsync(f.Admin, dev.Id, new SaveSecretRequest { Name = "bind/b", Type = SecretType.Generic, Payload = new SecretPayload { Value = "B" } }, null);

        await using (var db = await f.DbAsync())
        {
            var va = await db.SecretVersions.SingleAsync(v => v.SecretId == a);
            var vb = await db.SecretVersions.SingleAsync(v => v.SecretId == b);
            vb.WrappedDek = va.WrappedDek; // attacker with DB access swaps ciphertexts
            vb.Ciphertext = va.Ciphertext;
            await db.SaveChangesAsync();
        }
        await Assert.ThrowsAnyAsync<CryptographicException>(() => f.Secrets.RevealAsync(f.Admin, b, null, null));
    }
}

[Collection("server")]
public class AuditAndRetentionTests(ServerFixture f)
{
    [Fact]
    public async Task ChainVerifiesThenDetectsTampering()
    {
        await f.Audit.WriteAsync("tester", "test.event", AuditResult.Success, details: "one");
        await f.Audit.WriteAsync("tester", "test.event", AuditResult.Success, details: "two");
        Assert.True((await f.Audit.VerifyAsync()).Intact);

        long tamperedId;
        await using (var db = await f.DbAsync())
        {
            var row = await db.AuditEvents.Where(a => a.Details == "one").OrderByDescending(a => a.Id).FirstAsync();
            tamperedId = row.Id;
            row.Actor = "someone-else";
            await db.SaveChangesAsync();
        }

        var result = await f.Audit.VerifyAsync();
        Assert.False(result.Intact);
        Assert.Equal(tamperedId, result.FirstBrokenId);

        // Repair for the other tests sharing this server.
        await using (var db = await f.DbAsync())
        {
            var row = await db.AuditEvents.SingleAsync(a => a.Id == tamperedId);
            row.Actor = "tester";
            await db.SaveChangesAsync();
        }
        Assert.True((await f.Audit.VerifyAsync()).Intact);
    }

    [Fact]
    public async Task RetentionPurgesOldActivityAndKeepsChainVerifiable()
    {
        await using (var db = await f.DbAsync())
        {
            db.ActivityLogs.Add(new ActivityLog { Source = LogSource.Api, Path = "/old-api", TimestampUtc = DateTime.UtcNow.AddDays(-45) });
            db.ActivityLogs.Add(new ActivityLog { Source = LogSource.Api, Path = "/new-api", TimestampUtc = DateTime.UtcNow.AddDays(-1) });
            db.ActivityLogs.Add(new ActivityLog { Source = LogSource.Ui, Path = "/old-ui", TimestampUtc = DateTime.UtcNow.AddDays(-45) });
            await db.SaveChangesAsync();
        }

        var retention = f.App.Services.GetServices<Microsoft.Extensions.Hosting.IHostedService>().OfType<LogRetentionService>().Single();
        await retention.PurgeAsync(CancellationToken.None);

        await using (var db = await f.DbAsync())
        {
            Assert.False(await db.ActivityLogs.AnyAsync(a => a.Path == "/old-api" || a.Path == "/old-ui"));
            Assert.True(await db.ActivityLogs.AnyAsync(a => a.Path == "/new-api"));
        }

        // Audit purge (configured 0 = keep forever here) is exercised directly: the anchor keeps the remainder verifiable.
        await f.Audit.WriteAsync("tester", "before-cutoff", AuditResult.Success);
        var cutoff = DateTime.UtcNow.AddMilliseconds(1);
        await Task.Delay(20);
        await f.Audit.WriteAsync("tester", "after-cutoff", AuditResult.Success);
        Assert.True(await f.Audit.PurgeOlderThanAsync(cutoff) > 0);
        var v = await f.Audit.VerifyAsync();
        Assert.True(v.Intact, $"broken at {v.FirstBrokenId}");
        var (remaining, _) = await f.Audit.QueryAsync(new AuditQuery(Action: "before-cutoff"));
        Assert.Empty(remaining);
    }
}

public class StartupSafetyTests
{
    [Fact]
    public async Task RefusesToStartWithDifferentMasterKey()
    {
        var f = new ServerFixture();
        await f.InitializeAsync();
        var dev = f.Env("Dev");
        await f.Secrets.CreateAsync(f.Admin, dev.Id, new SaveSecretRequest { Name = "k/x", Type = SecretType.Generic, Payload = new SecretPayload { Value = "v" } }, null);
        await f.App.StopAsync();
        await f.App.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        await File.WriteAllTextAsync(f.KeyFile, MasterKey.GenerateBase64());
        var app = SecretManagerApp.Build(f.Args());
        var ex = await Assert.ThrowsAsync<InvalidOperationException>(() => SecretManagerApp.InitializeAsync(app));
        Assert.Contains("Refusing to start", ex.Message);
        await app.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(f.DataDir, true);
    }

    [Fact]
    public async Task SeedDemoRefusesAnInstanceThatAlreadyHasSecrets()
    {
        var f = new ServerFixture();
        await f.InitializeAsync();
        try
        {
            await f.Secrets.CreateAsync(f.Admin, f.Env("Dev").Id, new SaveSecretRequest { Name = "real/secret", Type = SecretType.Generic, Payload = new SecretPayload { Value = "v" } }, null);
            var exit = await DemoSeeder.RunAsync([.. f.Args(), "--seed-demo"]);
            Assert.Equal(2, exit);
            await using var db = await f.DbAsync();
            Assert.Equal(1, await db.Secrets.CountAsync()); // nothing added
        }
        finally
        {
            await f.DisposeAsync();
        }
    }

    [Fact]
    public void RefusesToStartWithoutMasterKey()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sm-nokey-" + Guid.NewGuid().ToString("N")[..8]);
        Assert.Throws<FileNotFoundException>(() => SecretManagerApp.Build([
            $"--SecretManager:DataPath={dir}", $"--SecretManager:MasterKeyFile={dir}/missing.key",
            "--SecretManager:Environments:0:Name=Dev", "--SecretManager:Environments:0:Port=9600",
        ]));
    }

    [Fact]
    public void RefusesDuplicatePorts()
    {
        var dir = Path.Combine(Path.GetTempPath(), "sm-dup-" + Guid.NewGuid().ToString("N")[..8]);
        Assert.Throws<InvalidOperationException>(() => SecretManagerApp.Build([
            $"--SecretManager:DataPath={dir}",
            "--SecretManager:Environments:0:Name=A", "--SecretManager:Environments:0:Port=9500",
            "--SecretManager:Environments:1:Name=B", "--SecretManager:Environments:1:Port=9500",
            "--SecretManager:Environments:2:Name=C", "--SecretManager:Environments:2:Port=9501",
            "--SecretManager:Environments:3:Name=D", "--SecretManager:Environments:3:Port=9502",
        ]));
    }
}

[Collection("server")]
public class EdgeHardeningTests(ServerFixture f)
{
    [Fact]
    public async Task HttpRedirectIgnoresForeignHostHeader()
    {
        using var http = f.Client();
        var req = new HttpRequestMessage(HttpMethod.Get, $"http://localhost:{f.HttpPort}/secrets");
        req.Headers.Host = "evil.example";
        var res = await http.SendAsync(req);
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.StartsWith("https://localhost:", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task SecurityHeadersArePresent()
    {
        using var http = f.Client();
        var ui = await http.GetAsync(f.AdminUrl("/Account/Login"));
        Assert.Contains("default-src 'self'", ui.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Contains("script-src 'self'", ui.Headers.GetValues("Content-Security-Policy").Single());
        Assert.Equal("DENY", ui.Headers.GetValues("X-Frame-Options").Single());
        Assert.True(ui.Headers.Contains("Strict-Transport-Security"));
        Assert.False(ui.Headers.Contains("Server"));
        var html = await ui.Content.ReadAsStringAsync();
        Assert.DoesNotMatch(@"<script(?![^>]*\bsrc=)[^>]*>", html); // no inline scripts
    }
}

using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Sockets;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Keyport.Core.Secrets;
using Keyport.Server.Configuration;
using Keyport.Server.Data;
using Keyport.Server.Edge;
using Keyport.Server.Services;

namespace Keyport.Tests;

[Collection("server")]
public class SecurityTests(ServerFixture f)
{
    // ---------- H3: testing a saved secret only ever uses its STORED settings ----------

    [Fact]
    public async Task StoredConnectionTestUsesStoredSettingsAndNeedsAReasonInProd()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        var prod = f.Env("Prod");
        var id = await f.Secrets.CreateAsync(f.Admin, prod.Id, new SaveSecretRequest
        {
            Name = "sec/pg-test", Type = new SecretType("PostgresConnection"),
            Metadata = SecretMetadata.From([new("host", "127.0.0.1"), new("port", port.ToString()), new("database", "d")]),
            Payload = SecretPayload.From([new("username", "u"), new("password", "Stored-Pw-1!")]),
            Reason = "test",
        }, null);

        await Assert.ThrowsAsync<ValidationException>(() => f.Secrets.TestStoredAsync(f.Admin, id, null, null));
        var result = await f.Secrets.TestStoredAsync(f.Admin, id, "CHG-1 check", null);
        Assert.True(result.Success, result.Message);

        var devOnly = new UserAccess("d", "dev-only", false, false, new Dictionary<int, EnvironmentRole> { [f.Env("Dev").Id] = EnvironmentRole.Editor });
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => f.Secrets.TestStoredAsync(devOnly, id, "x", null));

        var (events, _) = await f.Audit.QueryAsync(new AuditQuery(Action: "secret.test-connection", Target: "sec/pg-test"));
        Assert.Contains(events, e => e.Details is { } d && d.Contains("CHG-1 check") && d.Contains("stored settings"));
    }

    // ---------- Origin guard on the admin port ----------

    [Fact]
    public async Task CrossOriginStateChangesAndHubConnectionsAreRefused()
    {
        using var http = f.Client();
        foreach (var origin in new[] { "https://evil.example", $"https://localhost:{f.EnvPorts["Dev"]}" })
        {
            var post = new HttpRequestMessage(HttpMethod.Post, f.AdminUrl("/Account/Logout"));
            post.Headers.Add("Origin", origin);
            Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(post)).StatusCode);

            var hub = new HttpRequestMessage(HttpMethod.Post, f.AdminUrl("/_blazor/negotiate?negotiateVersion=1"));
            hub.Headers.Add("Origin", origin);
            Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(hub)).StatusCode);
        }

        var same = new HttpRequestMessage(HttpMethod.Post, f.AdminUrl("/Account/Logout"));
        same.Headers.Add("Origin", $"https://localhost:{f.AdminPort}");
        Assert.NotEqual(HttpStatusCode.Forbidden, (await http.SendAsync(same)).StatusCode);

        // Browsers with Referrer-Policy: no-referrer send "Origin: null" on same-origin form posts; Fetch Metadata decides.
        var browserSame = new HttpRequestMessage(HttpMethod.Post, f.AdminUrl("/Account/Logout"));
        browserSame.Headers.Add("Origin", "null");
        browserSame.Headers.Add("Sec-Fetch-Site", "same-origin");
        Assert.NotEqual(HttpStatusCode.Forbidden, (await http.SendAsync(browserSame)).StatusCode);

        foreach (var site in new[] { "same-site", "cross-site" })
        {
            var other = new HttpRequestMessage(HttpMethod.Post, f.AdminUrl("/Account/Logout"));
            other.Headers.Add("Sec-Fetch-Site", site);
            Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(other)).StatusCode);
        }
        var sandboxed = new HttpRequestMessage(HttpMethod.Post, f.AdminUrl("/Account/Logout"));
        sandboxed.Headers.Add("Origin", "null");
        Assert.Equal(HttpStatusCode.Forbidden, (await http.SendAsync(sandboxed)).StatusCode);
    }

    // ---------- M1: nothing but /Account until the password is changed and MFA enrolled ----------

    private async Task<(CookieContainer Jar, string UserId)> SignInNewUserAsync(bool mustChangePassword)
    {
        var name = "u" + Guid.NewGuid().ToString("N")[..8];
        var users = f.App.Services.GetRequiredService<UserAdminService>();
        var password = await users.CreateAsync(f.Admin, new SaveUserRequest { UserName = name, IsAdmin = true }, null);
        string id;
        await using (var db = await f.DbAsync())
        {
            var u = db.Users.Single(x => x.UserName == name);
            u.MustChangePassword = mustChangePassword;
            await db.SaveChangesAsync();
            id = u.Id;
        }

        var jar = new CookieContainer();
        using var http = f.Client(cookies: jar);
        var page = await http.GetStringAsync(f.AdminUrl("/Account/Login"));
        var input = Regex.Match(page, "<input[^>]*name=\"__RequestVerificationToken\"[^>]*>").Value;
        var token = Regex.Match(input, "value=\"([^\"]+)\"").Groups[1].Value;
        Assert.NotEmpty(token);
        var res = await http.PostAsync(f.AdminUrl("/Account/Login"), new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(token), ["_handler"] = "login",
            ["Input.UserName"] = name, ["Input.Password"] = password,
        }));
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Contains(jar.GetCookies(new Uri(f.AdminUrl("/"))), c => c.Name == "__Host-kp-auth");
        return (jar, id);
    }

    [Theory]
    [InlineData(true, "ChangePassword")]
    [InlineData(false, "EnableAuthenticator")]
    public async Task IncompleteAccountsCanOnlyReachAccountPages(bool mustChangePassword, string step)
    {
        var (jar, userId) = await SignInNewUserAsync(mustChangePassword);
        using var http = f.Client(cookies: jar);

        foreach (var page in new[] { "/", "/secrets", "/users", "/proxy" })
        {
            var r = await http.GetAsync(f.AdminUrl(page));
            Assert.Equal(HttpStatusCode.Redirect, r.StatusCode);
            Assert.Contains(step, r.Headers.Location!.ToString());
        }
        foreach (var path in new[] { "/admin/api/status", "/admin/api/audit", "/openapi/v1.json" })
            Assert.Equal(HttpStatusCode.Forbidden, (await http.GetAsync(f.AdminUrl(path))).StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, (await http.PostAsync(f.AdminUrl("/_blazor/negotiate?negotiateVersion=1"), null)).StatusCode);

        // The account pages themselves stay reachable.
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(f.AdminUrl("/Account/Manage/EnableAuthenticator"))).StatusCode);

        // Services refuse too, even for an admin.
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new Claim(ClaimTypes.NameIdentifier, userId), new Claim(ClaimTypes.Role, Roles.Admin)], "test"));
        await using var scope = f.App.Services.CreateAsyncScope();
        var access = await scope.ServiceProvider.GetRequiredService<AccessService>().ForPrincipalAsync(principal);
        Assert.False(access.IsAdmin);
        Assert.False(access.CanView(f.Env("Dev").Id));
    }
}

// ---------- M2: failed authentications are throttled per IP and the audit trail isn't flooded ----------

public class FailedAuthThrottleTests
{
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    [Fact]
    public void BlocksAnIpAfterTooManyFailuresAndAuditsOncePerReason()
    {
        var clock = new Clock();
        var t = new FailedAuthThrottle(clock, Options.Create(new KeyportOptions { Edge = new EdgeOptions { FailedAuthPerMinute = 30 } }));

        var audited = 0;
        for (var i = 0; i < 30; i++)
        {
            Assert.False(t.IsBlocked("10.0.0.9"));
            if (t.RecordFailure("10.0.0.9", "client:unknown|invalid key").Audit) audited++;
        }
        Assert.Equal(1, audited);
        Assert.True(t.IsBlocked("10.0.0.9"));
        Assert.False(t.IsBlocked("10.0.0.10"));          // other callers unaffected

        clock.Now += TimeSpan.FromMinutes(1);
        Assert.False(t.IsBlocked("10.0.0.9"));
        var (audit, suppressed) = t.RecordFailure("10.0.0.9", "client:unknown|invalid key");
        Assert.True(audit);
        Assert.Equal(29, suppressed);                     // the next audit entry says how many were folded in
    }
}

// ---------- M3: the connection tester can't be used to probe the server's own or metadata addresses ----------

public class ConnectionTesterTargetTests
{
    private static ConnectionTester Tester(Action<ConnectionTestOptions>? configure = null, int perMinute = 100)
    {
        var o = new KeyportOptions();
        o.ConnectionTest.PerUserPerMinute = perMinute;
        configure?.Invoke(o.ConnectionTest);
        return new ConnectionTester(Options.Create(o), TimeProvider.System);
    }

    private static SecretMetadata Meta(params (string K, string V)[] v) => SecretMetadata.From(v.Select(x => KeyValuePair.Create(x.K, (string?)x.V)));
    private static readonly SecretPayload Login = new() { Username = "u", Password = "p" };

    [Theory]
    [InlineData("127.0.0.1", "own address")]
    [InlineData("localhost", "own address")]
    [InlineData("169.254.169.254", "link-local")]
    [InlineData("::1", "own address")]
    [InlineData("0.0.0.0", "own address")]
    public async Task RefusesLocalAndMetadataTargets(string host, string expected)
    {
        var r = await Tester().TestAsync(new SecretType("PostgresConnection"), Meta(("host", host), ("port", "5432"), ("database", "d")), Login, "alice");
        Assert.False(r.Success);
        Assert.Contains(expected, r.Message);
    }

    [Fact]
    public async Task ChecksTheHostInsideAConnectionStringOverrideAndTnsDescriptor()
    {
        var sql = await Tester().TestAsync(SecretType.SqlServerConnection, new SecretMetadata(),
            new SecretPayload { ConnectionStringOverride = "Server=tcp:169.254.169.254,1433;User ID=u;Password=p" }, "alice");
        Assert.Contains("link-local", sql.Message);

        var ora = await Tester().TestAsync(SecretType.OracleConnection, new SecretMetadata(),
            new SecretPayload { ConnectionStringOverride = "User Id=u;Password=p;Data Source=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=127.0.0.1)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=X)))" }, "alice");
        Assert.Contains("own address", ora.Message);
    }

    [Fact]
    public async Task AllowListLimitsTargets()
    {
        var t = Tester(c => c.AllowedTargets.Add("10.20.0.0/16"));
        var r = await t.TestAsync(new SecretType("RedisConnection"), Meta(("host", "192.0.2.10"), ("port", "6379")), new SecretPayload(), "alice");
        Assert.Contains("not in the list", r.Message);
    }

    [Fact]
    public async Task EachPersonIsRateLimitedAndTestsCanBeTurnedOff()
    {
        var t = Tester(perMinute: 2);
        var meta = Meta(("host", "169.254.1.1"), ("port", "6379"));
        await t.TestAsync(new SecretType("RedisConnection"), meta, new SecretPayload(), "bob");
        await t.TestAsync(new SecretType("RedisConnection"), meta, new SecretPayload(), "bob");
        Assert.Contains("Too many tests", (await t.TestAsync(new SecretType("RedisConnection"), meta, new SecretPayload(), "bob")).Message);
        Assert.DoesNotContain("Too many tests", (await t.TestAsync(new SecretType("RedisConnection"), meta, new SecretPayload(), "carol")).Message);

        var off = Tester(c => c.Enabled = false);
        Assert.Contains("turned off", (await off.TestAsync(new SecretType("RedisConnection"), meta, new SecretPayload(), "bob")).Message);
    }
}

// ---------- M7: a generated root only vouches for Keyport's own names ----------

public class NameConstraintTests
{
    private static bool Chains(System.Security.Cryptography.X509Certificates.X509Certificate2 root, System.Security.Cryptography.X509Certificates.X509Certificate2 leaf)
    {
        using var chain = new System.Security.Cryptography.X509Certificates.X509Chain();
        chain.ChainPolicy.TrustMode = System.Security.Cryptography.X509Certificates.X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
        return chain.Build(leaf);
    }

    [Fact]
    public void RootWithConstraintsRejectsOtherNames()
    {
        var constraints = new Keyport.Core.Pki.NameConstraints(["keyport.corp.local"], [IPNetwork.Parse("10.0.0.0/8")]);
        using var root = Keyport.Core.Pki.CertificateAuthority.CreateRoot("Test Root", TimeSpan.FromDays(30), constraints);

        var read = Keyport.Core.Pki.NameConstraints.Read(root)!;
        Assert.Equal(["keyport.corp.local"], read.DnsNames);
        Assert.Equal(IPNetwork.Parse("10.0.0.0/8"), Assert.Single(read.IpRanges));
        Assert.Empty(read.Violations(["keyport.corp.local", "api.keyport.corp.local"], [IPAddress.Parse("10.1.2.3")]));
        Assert.Equal(["www.bank.example", "192.0.2.1"], read.Violations(["www.bank.example"], [IPAddress.Parse("192.0.2.1")]));

        using var ok = Keyport.Core.Pki.CertificateAuthority.IssueServerCertificate(root, ["keyport.corp.local"], [IPAddress.Parse("10.1.2.3")], TimeSpan.FromDays(1));
        using var bad = Keyport.Core.Pki.CertificateAuthority.IssueServerCertificate(root, ["www.bank.example"], [], TimeSpan.FromDays(1));
        Assert.True(Chains(root, ok));
        Assert.False(Chains(root, bad));     // the platform's chain builder enforces the constraint
    }

    [Fact]
    public void RootsCanStillBeCreatedWithoutConstraints()
    {
        using var root = Keyport.Core.Pki.CertificateAuthority.CreateRoot("Test Root", TimeSpan.FromDays(30));
        Assert.Null(Keyport.Core.Pki.NameConstraints.Read(root));
    }
}

// ---------- M8: absolute session lifetime and step-up ----------

public class SessionSecurityTests
{
    private sealed class Clock : TimeProvider
    {
        public DateTimeOffset Now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static ClaimsPrincipal SignedInAt(DateTimeOffset t) =>
        new(new ClaimsIdentity([SessionSecurity.NewAuthTimeClaim(t)], "test"));

    [Fact]
    public void SessionsEndAfterTheAbsoluteLifetimeAndOldCookiesAreRejected()
    {
        var o = new AuthOptions { AbsoluteSessionHours = 8 };
        var now = DateTimeOffset.UtcNow;
        Assert.False(SessionSecurity.IsExpired(SignedInAt(now.AddHours(-7)), o, now));
        Assert.True(SessionSecurity.IsExpired(SignedInAt(now.AddHours(-9)), o, now));
        Assert.True(SessionSecurity.IsExpired(new ClaimsPrincipal(new ClaimsIdentity("test")), o, now));   // no sign-in time
    }

    [Fact]
    public void StepUpIsNeededOnlyWhenSignInAndLastCodeAreOld()
    {
        var clock = new Clock();
        var o = new AuthOptions { StepUpMinutes = 15 };
        var session = new CircuitSession(clock);

        Assert.False(session.NeedsStepUp(SignedInAt(clock.Now.AddMinutes(-5)), o));
        var signedInLongAgo = SignedInAt(clock.Now.AddHours(-2));
        Assert.True(session.NeedsStepUp(signedInLongAgo, o));

        session.SteppedUp();
        Assert.False(session.NeedsStepUp(signedInLongAgo, o));
        clock.Now += TimeSpan.FromMinutes(16);
        Assert.True(session.NeedsStepUp(signedInLongAgo, o));
    }
}

// ---------- M4: the first admin's password is never logged ----------

[Collection("server")]
public class BootstrapPasswordTests(ServerFixture f)
{
    [Fact]
    public void OneTimePasswordIsInAPrivateFileNotTheLog()
    {
        var path = Path.Combine(f.DataDir, BootstrapAdmin.FileName);
        Assert.True(File.Exists(path));
        Assert.Matches(@"password: \S{20}", File.ReadAllText(path));
        if (!OperatingSystem.IsWindows())
            Assert.Equal(UnixFileMode.UserRead | UnixFileMode.UserWrite, File.GetUnixFileMode(path));
    }
}

// ---------- L1–L3 ----------

public class LowSeverityHardeningTests
{
    [Fact]
    public void UpstreamGuardRefusesMetadataAndLoopbackUnlessAllowListed()
    {
        var open = new ProxyOptions();
        Assert.Contains("link-local", UpstreamGuard.Check("evil.example", [IPAddress.Parse("169.254.169.254")], open));
        Assert.Contains("own address", UpstreamGuard.Check("sneaky.example", [IPAddress.Parse("127.0.0.1")], open));
        Assert.Null(UpstreamGuard.Check("grafana.corp", [IPAddress.Parse("10.1.2.3")], open));

        var listed = new ProxyOptions { AllowedUpstreams = ["127.0.0.1/32"] };
        Assert.Null(UpstreamGuard.Check("localhost", [IPAddress.Parse("127.0.0.1")], listed));
        Assert.Contains("link-local", UpstreamGuard.Check("x", [IPAddress.Parse("169.254.1.1")], new ProxyOptions { AllowedUpstreams = ["169.254.0.0/16"] }));
    }

    [Fact]
    public void SlowPatternsTimeOutInsteadOfHanging()
    {
        var def = new Keyport.Core.Secrets.Types.SecretTypeDefinition
        {
            Key = "Slow", Title = "Slow", Category = Keyport.Core.Secrets.Types.Categories.Other,
            Fields = [new() { Key = "v", Label = "Value", Pattern = "^(a+)+$" }],
        };
        var reg = Keyport.Core.Secrets.Types.SecretTypeRegistry.Create([def]);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var errors = reg.Validate(def, new Dictionary<string, string?> { ["v"] = new string('a', 40) + "!" });
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(2));
        Assert.Contains(errors, e => e.Contains("invalid format"));
    }

    [Fact]
    public void EveryUiPageIsReservedFromProxyRoutes()
    {
        Assert.Contains("help", ProxyRouteService.ReservedSegments);
        Assert.Contains("secret-types", ProxyRouteService.ReservedSegments);
        Assert.Contains("Account", ProxyRouteService.ReservedSegments);
    }
}

// ---------- L5: authenticator keys and recovery codes are encrypted at rest ----------

[Collection("server")]
public class ProtectedTokenTests(ServerFixture f)
{
    [Fact]
    public async Task AuthenticatorKeysAndRecoveryCodesAreEncryptedButStillWork()
    {
        var name = "t" + Guid.NewGuid().ToString("N")[..8];
        await f.App.Services.GetRequiredService<UserAdminService>().CreateAsync(f.Admin, new SaveUserRequest { UserName = name }, null);

        await using var scope = f.App.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<ApplicationUser>>();
        Assert.True(users.SupportsUserPasskey);                   // the custom store keeps passkey support
        var user = (await users.FindByNameAsync(name))!;
        await users.ResetAuthenticatorKeyAsync(user);
        var key = await users.GetAuthenticatorKeyAsync(user);
        var codes = (await users.GenerateNewTwoFactorRecoveryCodesAsync(user, 3))!.ToList();

        await using (var db = await f.DbAsync())
        {
            var stored = db.UserTokens.Where(t => t.UserId == user.Id).ToList();
            Assert.Equal(2, stored.Count);
            Assert.All(stored, t => Assert.StartsWith("kp-enc:v1:", t.Value));
            Assert.DoesNotContain(stored, t => t.Value!.Contains(key!) || t.Value.Contains(codes[0]));
        }

        Assert.Equal(key, await users.GetAuthenticatorKeyAsync(user));
        Assert.Equal(3, await users.CountRecoveryCodesAsync(user));
        Assert.True((await users.RedeemTwoFactorRecoveryCodeAsync(user, codes[0])).Succeeded);
        Assert.Equal(2, await users.CountRecoveryCodesAsync(user));
    }

    [Fact]
    public async Task TokensStoredInClearByOlderVersionsAreEncryptedAtStartup()
    {
        var name = "l" + Guid.NewGuid().ToString("N")[..8];
        await f.App.Services.GetRequiredService<UserAdminService>().CreateAsync(f.Admin, new SaveUserRequest { UserName = name }, null);
        await using var db = await f.DbAsync();
        var id = db.Users.Single(u => u.UserName == name).Id;
        db.UserTokens.Add(new Microsoft.AspNetCore.Identity.IdentityUserToken<string>
            { UserId = id, LoginProvider = "[AspNetUserStore]", Name = "AuthenticatorKey", Value = "LEGACYCLEARKEY234" });
        await db.SaveChangesAsync();

        Assert.True(await ProtectedTokens.EncryptExistingAsync(db, f.App.Services.GetRequiredService<Keyport.Core.Crypto.EnvelopeEncryptor>()) >= 1);
        db.ChangeTracker.Clear();
        Assert.StartsWith("kp-enc:v1:", db.UserTokens.Single(t => t.UserId == id).Value);

        await using var scope = f.App.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<ApplicationUser>>();
        Assert.Equal("LEGACYCLEARKEY234", await users.GetAuthenticatorKeyAsync((await users.FindByIdAsync(id))!));
    }
}

public class KekRotationTests
{
    [Fact]
    public async Task RotationRewrapsSecretsAndAuthenticatorTokens()
    {
        var f = new ServerFixture();
        await f.InitializeAsync();
        string userId, key;
        var secretId = await f.Secrets.CreateAsync(f.Admin, f.Env("Dev").Id, new SaveSecretRequest
            { Name = "rot/x", Type = SecretType.Generic, Payload = new SecretPayload { Value = "survives-rotation" } }, null);
        await f.App.Services.GetRequiredService<UserAdminService>().CreateAsync(f.Admin, new SaveUserRequest { UserName = "rotuser" }, null);
        await using (var scope = f.App.Services.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<ApplicationUser>>();
            var u = (await users.FindByNameAsync("rotuser"))!;
            await users.ResetAuthenticatorKeyAsync(u);
            (userId, key) = (u.Id, (await users.GetAuthenticatorKeyAsync(u))!);
        }
        await f.App.StopAsync();
        await f.App.DisposeAsync();
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

        var newKey = Path.Combine(f.DataDir, "new.key");
        await File.WriteAllTextAsync(newKey, Keyport.Core.Crypto.MasterKey.GenerateBase64());
        Assert.Equal(0, await Keyport.Server.Cli.RunAsync([.. f.Args(), "--rotate-kek", newKey]));
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        File.Copy(newKey, f.KeyFile, overwrite: true);

        var app = Keyport.Server.KeyportApp.Build(f.Args());
        try
        {
            await Keyport.Server.KeyportApp.InitializeAsync(app);
            Assert.Equal("survives-rotation", (await app.Services.GetRequiredService<SecretService>().RevealAsync(f.Admin, secretId, null, null)).Value);
            await using var scope = app.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<Microsoft.AspNetCore.Identity.UserManager<ApplicationUser>>();
            Assert.Equal(key, await users.GetAuthenticatorKeyAsync((await users.FindByIdAsync(userId))!));
        }
        finally
        {
            await app.DisposeAsync();
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(f.DataDir, true); } catch (IOException) { }
        }
    }
}

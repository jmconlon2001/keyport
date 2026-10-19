using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Keyport.Core.Crypto;
using Keyport.Core.Secrets;
using Keyport.Server.Configuration;
using Keyport.Server.Data;
using Keyport.Server.Services;

namespace Keyport.Server;

/// <summary>
/// <c>--seed-demo</c>: fills an EMPTY instance with demo data for the fictional company "Nimbus Orbital"
/// (users, secrets in every environment, applications, proxy routes, audit history), then runs the server and
/// generates some live API traffic so dashboards have numbers. Refuses to touch an instance that has secrets.
/// API keys are only used in memory; nothing is written to disk.
/// </summary>
public static class DemoSeeder
{
    private const string Domain = "nimbus.internal";

    private sealed record DemoSecret(string Name, SecretType Type, string Description, string? Host = null, int? Port = null,
        string? Db = null, string? Service = null, string? User = null, string? Domain = null, string? Url = null, string? Tags = null,
        string[]? Envs = null, int Versions = 1, int? RotateInDays = null, (string Key, string Value)[]? Fields = null);

    private static readonly DemoSecret[] Secrets =
    [
        new("orion-ledger/oracle-core", SecretType.OracleConnection, "Orion Ledger general ledger. Owner: Finance Platform squad",
            Host: "orion-ora-{env}-01." + Domain, Port: 1521, Service: "LEDGERPDB", User: "orion_app", Tags: "finance, tier-1", Versions: 3, RotateInDays: 40),
        new("orion-ledger/sql-reporting", SecretType.SqlServerConnection, "Read-only replica for month-end reports",
            Host: "orion-sql-{env}." + Domain, Db: "LedgerReporting", User: "svc_orion_ro", Tags: "finance, reporting", Versions: 2),
        new("orion-ledger/eu/sql-frankfurt", SecretType.SqlServerConnection, "EU data-residency replica (Frankfurt)",
            Host: "fra-sql-{env}." + Domain, Db: "LedgerEU", User: "svc_orion_eu", Tags: "finance, gdpr", Envs: ["Dev", "Test", "Prod"]),
        new("helios-payroll/oracle-hr", SecretType.OracleConnection, "Helios payroll and HR records. Owner: People Systems",
            Host: "helios-ora-{env}." + Domain, Service: "HRPDB", User: "helios_app", Tags: "hr, pii, tier-1", Versions: 4, RotateInDays: -6),
        new("helios-payroll/svc-batch", SecretType.ServiceAccount, "Runs the nightly Helios payroll batch",
            Domain: "NIMBUS", User: "svc_helios_batch", Url: "Helios nightly payroll run", Tags: "hr, batch", Versions: 2, RotateInDays: 12),
        new("nebula-crm/salesforce-api", SecretType.BasicAuth, "Nebula CRM integration user for the Salesforce REST API",
            Url: "https://crm.example.com/nimbus-orbital/api/v61", User: "nebula.integration@" + Domain, Tags: "crm, saas", Envs: ["Dev", "Test", "Prod"], Versions: 2),
        new("atlas-inventory/sql-main", SecretType.SqlServerConnection, "Atlas spare-parts inventory for the launch depots",
            Host: "atlas-sql-{env}." + Domain, Port: 14330, Db: "AtlasInventory", User: "svc_atlas", Tags: "logistics", Envs: ["Dev", "Test", "Upgrade"]),
        new("atlas-inventory/svc-scanner", SecretType.ServiceAccount, "Hangar barcode scanners sync account",
            Domain: "NIMBUS", User: "svc_atlas_scan", Url: "Hangar 7 scanner fleet", Tags: "logistics, iot", Envs: ["Dev", "Test", "Upgrade", "Prod"]),
        new("pulsar-notify/smtp-relay", SecretType.BasicAuth, "Outbound mail relay for Pulsar notifications",
            Url: "smtp://relay." + Domain + ":587", User: "pulsar-mailer", Tags: "messaging", Versions: 2),
        new("pulsar-notify/push-gateway-token", SecretType.Generic, "Push gateway API token for crew mobile alerts", Tags: "messaging, mobile", RotateInDays: 75),
        new("quasar-analytics/warehouse-svc", SecretType.ServiceAccount, "Quasar telemetry warehouse loader",
            Domain: "NIMBUS", User: "svc_quasar_etl", Url: "Telemetry warehouse nightly load", Tags: "analytics", Envs: ["Dev", "Test"]),
        new("vega-telemetry/oracle-timeseries", SecretType.OracleConnection, "Vega flight telemetry time-series store",
            Host: "vega-ora-{env}." + Domain, Service: "TELEMPDB", User: "vega_ingest", Tags: "telemetry, tier-1", Envs: ["Dev", "Test", "Upgrade", "Prod"], Versions: 2),
        new("shared/license-starchart", SecretType.Generic, "StarChart route-planning licence key", Tags: "licensing", Envs: ["Prod", "Upgrade"]),
        new("quasar-analytics/postgres-lakehouse", new("PostgresConnection"), "Quasar lakehouse catalogue (PostgreSQL)",
            Host: "quasar-pg-{env}." + Domain, Db: "lakehouse", User: "quasar_catalog", Tags: "analytics, postgres", Envs: ["Dev", "Test", "Prod"], Versions: 2,
            Fields: [("sslMode", "VerifyFull")]),
        new("pulsar-notify/redis-queue", new("RedisConnection"), "Pulsar alert fan-out queue (Redis)",
            Host: "pulsar-redis-{env}." + Domain, Port: 6380, User: "pulsar-worker", Tags: "messaging, cache", Fields: [("tls", "true")]),
        new("mission-control/portal-tls", new("TlsCertificate"), "TLS certificate for the Mission Control portal",
            Host: "portal.{env}." + Domain, Tags: "certificates, web", Envs: ["Test", "Upgrade", "Prod"]),
    ];

    private sealed record DemoApp(string Name, string Owner, string[] Grants, int KeyAgeDays, string[]? Envs = null, bool Disabled = false, string? Cidrs = null, int? ExpiresInDays = null);

    private static readonly DemoApp[] Apps =
    [
        new("orion-ledger-api", "Finance Platform squad · ava.sterling@" + Domain, ["orion-ledger/*"], 120),
        new("helios-payroll-batch", "People Systems · nights on-call", ["helios-payroll/*"], 430, Cidrs: "10.40.0.0/16"),
        new("nebula-crm-sync", "Revenue Ops · marcus.vega@" + Domain, ["nebula-crm/salesforce-api", "pulsar-notify/smtp-relay"], 45, Envs: ["Dev", "Test", "Prod"]),
        new("atlas-hangar-scanners", "Logistics Engineering", ["atlas-inventory/*"], 9),
        new("pulsar-notify", "Crew Comms team", ["pulsar-notify/*"], 200, ExpiresInDays: 60),
        new("vega-ingest", "Flight Data team · leo.okafor@" + Domain, ["vega-telemetry/oracle-timeseries"], 30),
        new("quasar-loader", "Data & Insights", ["quasar-analytics/*", "vega-telemetry/oracle-timeseries"], 600, Envs: ["Dev", "Test"], Disabled: true),
        new("mission-control-portal", "Mission Control web team", ["orion-ledger/sql-reporting", "atlas-inventory/*", "mission-control/*", "shared/*"], 75, Envs: ["Test", "Upgrade", "Prod"]),
    ];

    private sealed record DemoUser(string UserName, string Display, bool Admin, bool Auditor, Dictionary<string, EnvironmentRole> Roles);

    private static readonly DemoUser[] Users =
    [
        new("ava.sterling", "Ava Sterling", true, false, new()),
        new("marcus.vega", "Marcus Vega", false, false, new() { ["Dev"] = EnvironmentRole.Editor, ["Test"] = EnvironmentRole.Editor, ["Upgrade"] = EnvironmentRole.Viewer, ["Prod"] = EnvironmentRole.Viewer }),
        new("priya.raman", "Priya Raman", false, true, new()),
        new("leo.okafor", "Leo Okafor", false, false, new() { ["Upgrade"] = EnvironmentRole.Editor, ["Prod"] = EnvironmentRole.Editor }),
        new("nina.castellanos", "Nina Castellanos", false, false, new() { ["Dev"] = EnvironmentRole.Viewer }),
        new("kai.thornton", "Kai Thornton", false, false, new() { ["Dev"] = EnvironmentRole.Editor, ["Test"] = EnvironmentRole.Editor }),
    ];

    public static async Task<int> RunAsync(string[] args)
    {
        var app = KeyportApp.Build(args.Where(a => a != "--seed-demo").ToArray());
        await KeyportApp.InitializeAsync(app);
        var log = app.Services.GetRequiredService<ILoggerFactory>().CreateLogger("Keyport.Demo");
        var sp = app.Services;

        await using (var db = await sp.GetRequiredService<IDbContextFactory<ApplicationDbContext>>().CreateDbContextAsync())
        {
            if (await db.Secrets.AnyAsync())
            {
                log.LogError("--seed-demo refused: this instance already contains secrets. Demo data is only added to an empty instance.");
                return 2;
            }
        }

        log.LogWarning("DEMO MODE: seeding fictional 'Nimbus Orbital' data. Do not use this instance for real secrets.");
        var rng = new Random(2026);
        var envs = sp.GetRequiredService<EnvironmentRegistry>();
        var secrets = sp.GetRequiredService<SecretService>();
        var clients = sp.GetRequiredService<ApiClientService>();
        var audit = sp.GetRequiredService<AuditService>();

        // ---- Users ----
        var access = new Dictionary<string, UserAccess>();
        var demoPassword = PasswordGenerator.Generate(18);
        await using (var scope = sp.CreateAsyncScope())
        {
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            foreach (var u in Users)
            {
                var user = new ApplicationUser { UserName = u.UserName, DisplayName = u.Display, CreatedUtc = DateTime.UtcNow.AddDays(-rng.Next(30, 400)) };
                var r = await users.CreateAsync(user, demoPassword);
                if (!r.Succeeded) throw new InvalidOperationException(string.Join("; ", r.Errors.Select(e => e.Description)));
                if (u.Admin) await users.AddToRoleAsync(user, Roles.Admin);
                if (u.Auditor) await users.AddToRoleAsync(user, Roles.Auditor);
                var roles = new Dictionary<int, EnvironmentRole>();
                foreach (var (envName, role) in u.Roles)
                {
                    var e = envs.ByName(envName)!;
                    db.UserEnvironmentRoles.Add(new UserEnvironmentRole { UserId = user.Id, EnvironmentId = e.Id, Role = role });
                    roles[e.Id] = role;
                }
                await db.SaveChangesAsync();
                access[u.UserName] = new UserAccess(user.Id, u.UserName, u.Admin, u.Auditor, roles);
                await audit.WriteAsync("admin", "user.create", AuditResult.Success, target: u.UserName, clientIp: "10.20.1.15",
                    details: u.Admin ? "Admin" : u.Auditor ? "Auditor" : string.Join(", ", u.Roles.Select(kv => $"{kv.Key}:{kv.Value}")));
            }
        }
        var ava = access["ava.sterling"];
        var editorsByEnv = new Dictionary<string, UserAccess> { ["Dev"] = access["marcus.vega"], ["Test"] = access["kai.thornton"], ["Upgrade"] = access["leo.okafor"], ["Prod"] = access["leo.okafor"] };

        // ---- Secrets ----
        var ips = new[] { "10.20.1.15", "10.20.1.42", "10.20.3.7", "10.20.4.19" };
        foreach (var s in Secrets)
        {
            foreach (var env in envs.All.Where(e => s.Envs is null || s.Envs.Contains(e.Name)))
            {
                var actor = env.Protected ? access["leo.okafor"] : editorsByEnv[env.Name];
                var tag = env.Name.ToLowerInvariant();
                var meta = new SecretMetadata
                {
                    Description = s.Description,
                    Host = s.Host?.Replace("{env}", tag),
                    Port = s.Port,
                    Database = s.Db,
                    ServiceName = s.Service,
                    Domain = s.Domain,
                    Url = s.Url,
                    Encrypt = "Mandatory",
                    ApplicationName = s.Type == SecretType.SqlServerConnection ? s.Name.Split('/')[0] : null,
                };
                foreach (var (k, v) in s.Fields ?? []) meta[k] = v;
                string? tlsKey = null;
                if (s.Type.Key == "TlsCertificate")
                {
                    // A real (self-signed) certificate and matching key, so the PEM checks pass.
                    using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
                    var req = new CertificateRequest($"CN={meta.Host}", key, HashAlgorithmName.SHA256);
                    var san = new SubjectAlternativeNameBuilder();
                    san.AddDnsName(meta.Host!);
                    req.CertificateExtensions.Add(san.Build());
                    using var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-20), DateTimeOffset.UtcNow.AddDays(70));
                    meta["certificate"] = cert.ExportCertificatePem();
                    tlsKey = key.ExportPkcs8PrivateKeyPem();
                }
                SecretPayload Payload() => s.Type == SecretType.Generic
                    ? new SecretPayload { Value = "nmb_" + PasswordGenerator.Generate(40, symbols: false) }
                    : tlsKey is not null
                    ? SecretPayload.From([KeyValuePair.Create("privateKey", (string?)tlsKey)])
                    : new SecretPayload { Username = s.User + (s.Type == SecretType.OracleConnection || s.Type == SecretType.SqlServerConnection ? (env.Name == "Prod" ? "" : "_" + tag) : ""), Password = PasswordGenerator.Generate(24) };

                var id = await secrets.CreateAsync(actor, env.Id, new SaveSecretRequest
                {
                    Name = s.Name, Type = s.Type, Metadata = meta, Tags = s.Tags, Payload = Payload(),
                    RotateAfterUtc = s.RotateInDays is { } d ? DateTime.UtcNow.Date.AddDays(env.Protected ? d : d + 30) : null,
                    Comment = "imported from legacy WCF service", Reason = env.Protected ? "CHG-4471 migrate from WCF" : null,
                }, ips[rng.Next(ips.Length)]);

                for (var v = 2; v <= s.Versions; v++)
                {
                    await secrets.UpdateAsync(actor, id, new SaveSecretRequest
                    {
                        Metadata = meta, Tags = s.Tags, RotateAfterUtc = s.RotateInDays is { } d2 ? DateTime.UtcNow.Date.AddDays(d2) : null,
                        Payload = Payload(), Comment = v % 2 == 0 ? "quarterly password rotation" : "rotated after DBA maintenance",
                        Reason = env.Protected ? $"CHG-{4500 + v * 13}" : null,
                    }, ips[rng.Next(ips.Length)]);
                }
            }
        }

        // A few human reveals and copies, so the audit trail tells a story.
        await using (var db = await sp.GetRequiredService<IDbContextFactory<ApplicationDbContext>>().CreateDbContextAsync())
        {
            var prod = envs.ByName("Prod")!;
            var prodIds = await db.Secrets.Where(x => x.EnvironmentId == prod.Id).Select(x => x.Id).Take(3).ToListAsync();
            foreach (var pid in prodIds)
                await secrets.RevealAsync(access["leo.okafor"], pid, "INC-2291 investigating failed nightly batch", "10.20.4.19");
            var dev = envs.ByName("Dev")!;
            var devId = await db.Secrets.Where(x => x.EnvironmentId == dev.Id).Select(x => x.Id).FirstAsync();
            await secrets.RevealAsync(access["marcus.vega"], devId, null, "10.20.1.42");
        }

        // ---- Applications ----
        var keys = new List<(string Env, string App, string Key, string[] Grants)>();
        foreach (var a in Apps)
        {
            foreach (var env in envs.All.Where(e => a.Envs is null || a.Envs.Contains(e.Name)))
            {
                // Only grant what exists in this environment (the server refuses grants that match nothing).
                var valid = (await clients.GrantOptionsAsync(ava, env.Id)).Select(o => o.Pattern).ToHashSet();
                var grants = a.Grants.Where(valid.Contains).ToArray();
                if (grants.Length == 0) continue;
                var (client, key) = await clients.CreateAsync(env.Protected ? ava : editorsByEnv[env.Name], env.Id, new SaveApiClientRequest
                {
                    Name = a.Name, Description = a.Owner, Grants = string.Join('\n', grants), AllowedCidrs = a.Cidrs,
                    ExpiresUtc = a.ExpiresInDays is { } x ? DateTime.UtcNow.Date.AddDays(x) : null,
                    Reason = env.Protected ? "CHG-4471 migrate from WCF" : null,
                }, "10.20.1.15");
                if (a.Disabled) await clients.SetDisabledAsync(ava, client.Id, true, "Quasar decommission in progress", "10.20.1.15");
                else if (a.Cidrs is null) keys.Add((env.Name, a.Name, key, grants)); // network-restricted apps can't call from here
            }
        }

        // ---- Reverse proxy routes ----
        var proxy = sp.GetRequiredService<ProxyRouteService>();
        // Environment ports only: routes are never served on the admin port (they'd share the admin UI's origin).
        int Port(string env) => envs.All.First(e => e.Name == env).Port;
        foreach (var (name, desc, upstream, accessLevel, enabled, env) in new[]
        {
            ("grafana", "Fleet observability dashboards", "http://grafana." + Domain + ":3000/", ProxyAccess.SignedIn, true, "Prod"),
            ("runbooks", "Mission Control runbooks wiki", "http://runbooks." + Domain + ":8080/", ProxyAccess.SignedIn, true, "Prod"),
            ("status-board", "Public launch status board", "http://statusboard." + Domain + "/", ProxyAccess.Anonymous, true, "Prod"),
            ("kibana", "Legacy log search (retiring)", "http://kibana." + Domain + ":5601/", ProxyAccess.Admins, false, "Test"),
        })
        {
            try
            {
                await proxy.CreateAsync(ava, new SaveProxyRouteRequest
                {
                    Name = name, Description = desc, PathPrefix = "/" + name, Destinations = upstream, Ports = [Port(env)],
                    Access = accessLevel, RelaxCsp = name is "grafana" or "kibana", Enabled = enabled, Reason = "Publish internal tools via Keyport edge",
                }, "10.20.1.15");
            }
            catch (System.ComponentModel.DataAnnotations.ValidationException ex)
            {
                log.LogWarning("Demo proxy route {Name} skipped: {Message}", name, ex.Message);
            }
        }

        // ---- Some security noise for the audit trail ----
        await audit.WriteAsync("ava.sterling", "auth.login", AuditResult.Success, clientIp: "10.20.1.15", details: "passkey");
        await audit.WriteAsync("priya.raman", "auth.login", AuditResult.Success, clientIp: "10.20.2.88", details: "authenticator");
        await audit.WriteAsync("unknown-admin", "auth.login", AuditResult.Failure, clientIp: "203.0.113.77", details: "invalid credentials");
        await audit.WriteAsync("unknown-admin", "auth.login", AuditResult.Failure, clientIp: "203.0.113.77", details: "invalid credentials");
        await audit.WriteAsync("priya.raman", "audit.verify", AuditResult.Success, clientIp: "10.20.2.88", details: "chain intact");

        // ---- Make history look lived-in (does not touch the hash-chained audit trail) ----
        await using (var db = await sp.GetRequiredService<IDbContextFactory<ApplicationDbContext>>().CreateDbContextAsync())
        {
            foreach (var s in await db.Secrets.Include(x => x.Versions).ToListAsync())
            {
                var created = DateTime.UtcNow.AddDays(-rng.Next(150, 420)).AddMinutes(-rng.Next(0, 1440));
                s.CreatedUtc = created;
                var versions = s.Versions.OrderBy(v => v.Version).ToList();
                var step = (DateTime.UtcNow - created).TotalDays / (versions.Count + 1);
                for (var i = 0; i < versions.Count; i++)
                    versions[i].CreatedUtc = created.AddDays(step * i).AddHours(rng.Next(0, 9));
                s.UpdatedUtc = versions[^1].CreatedUtc;
            }
            foreach (var c in await db.ApiClients.Include(x => x.Environment).ToListAsync())
            {
                var demo = Apps.First(a => a.Name == c.Name);
                c.KeyCreatedUtc = DateTime.UtcNow.AddDays(-demo.KeyAgeDays - rng.Next(0, 5)).AddHours(-rng.Next(0, 20));
                c.CreatedUtc = c.KeyCreatedUtc.AddDays(-rng.Next(0, 90));
            }
            await db.SaveChangesAsync();
        }

        // ---- Serve, and generate live traffic so the status page has real numbers ----
        await app.StartAsync();
        log.LogWarning("""

            ================================================================
              DEMO data loaded (fictional company: Nimbus Orbital)
              Demo users (password for all): {Password}
                ava.sterling (Admin) · priya.raman (Auditor) · marcus.vega
                leo.okafor · nina.castellanos · kai.thornton
              Each must enrol MFA at first sign-in.
            ================================================================
            """, demoPassword);
        _ = Task.Run(() => GenerateTrafficAsync(sp, envs, keys, log));
        await app.WaitForShutdownAsync();
        return 0;
    }

    private static async Task GenerateTrafficAsync(IServiceProvider sp, EnvironmentRegistry envs, List<(string Env, string App, string Key, string[] Grants)> keys, ILogger log)
    {
        try
        {
            var ca = sp.GetRequiredService<CertificateManager>().TrustAnchor;
            using var handler = new SocketsHttpHandler
            {
                SslOptions = { CertificateChainPolicy = new X509ChainPolicy { TrustMode = X509ChainTrustMode.CustomRootTrust, CustomTrustStore = { ca }, RevocationMode = X509RevocationMode.NoCheck } },
            };
            using var http = new HttpClient(handler);
            var names = await sp.GetRequiredService<IDbContextFactory<ApplicationDbContext>>().CreateDbContext()
                .Secrets.Select(s => new { s.Name, s.Type, Env = s.Environment.Name }).ToListAsync();
            var rng = new Random(7);
            var ok = 0;

            for (var i = 0; i < 420; i++)
            {
                var k = keys[rng.Next(keys.Count)];
                var env = envs.ByName(k.Env)!;
                var port = env.Port;
                var candidates = names.Where(n => n.Env == k.Env && k.Grants.Any(g => SecretNames.MatchesGrant(n.Name, g))).ToList();
                string path;
                var roll = rng.NextDouble();
                if (roll < 0.04) port = envs.All.First(e => e.Name != k.Env).Port;            // wrong environment → 401
                if (roll is >= 0.04 and < 0.08 || candidates.Count == 0) path = "/api/v1/secrets/" + k.Grants[0].TrimEnd('*', '/') + "/legacy-missing"; // → 404
                else if (roll < 0.14) path = "/api/v1/status";
                else
                {
                    var c = candidates[rng.Next(candidates.Count)];
                    path = $"/api/v1/{(c.Type.IsConnection() ? "connections" : c.Type.IsCredential() ? "credentials" : "secrets")}/{c.Name}";
                }
                using var req = new HttpRequestMessage(HttpMethod.Get, $"https://localhost:{port}{path}");
                req.Headers.Authorization = new("Bearer", k.Key);
                req.Headers.UserAgent.ParseAdd($"{k.App}/2.{rng.Next(0, 9)}.{rng.Next(0, 30)}");
                using var res = await http.SendAsync(req);
                if (res.IsSuccessStatusCode) ok++;
                await Task.Delay(rng.Next(5, 40));
            }
            log.LogInformation("Demo traffic generated ({Ok} successful reads).", ok);
        }
        catch (Exception ex)
        {
            log.LogWarning(ex, "Demo traffic generation stopped");
        }
    }
}

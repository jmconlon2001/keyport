using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Keyport.Server.Data;
using Keyport.Server.Services;

namespace Keyport.Tests;

/// <summary>A tiny upstream service that echoes what it received.</summary>
public sealed class Upstream : IAsyncDisposable
{
    private readonly WebApplication _app;
    public string Url { get; }

    private Upstream(WebApplication app, string url)
    {
        _app = app;
        Url = url;
    }

    public static async Task<Upstream> StartAsync()
    {
        var b = WebApplication.CreateSlimBuilder();
        b.WebHost.UseUrls("http://127.0.0.1:0");
        b.Logging.ClearProviders();
        var app = b.Build();
        app.MapGet("/healthz", () => "ok");
        // Echoes the credentials-related headers it received.
        app.MapGet("/headers", (HttpContext ctx) => Results.Json(new Dictionary<string, string>
        {
            ["cookie"] = ctx.Request.Headers.Cookie.ToString(),
            ["authorization"] = ctx.Request.Headers.Authorization.ToString(),
            ["x-api-key"] = ctx.Request.Headers["X-Api-Key"].ToString(),
        }));
        // Tries to plant Keyport's own cookies.
        app.MapGet("/set-cookies", (HttpContext ctx) =>
        {
            ctx.Response.Headers.Append("Set-Cookie", "__Host-kp-auth=planted; Path=/; Secure; HttpOnly");
            ctx.Response.Headers.Append("Set-Cookie", ".AspNetCore.Identity.Application=planted; Path=/");
            ctx.Response.Headers.Append("Set-Cookie", "upstream-pref=dark; Path=/");
            return "ok";
        });
        app.Map("/{**path}", (HttpContext ctx) => Results.Text($"upstream path={ctx.Request.Path}"));
        await app.StartAsync();
        return new Upstream(app, app.Urls.First().TrimEnd('/') + "/");
    }

    public async ValueTask DisposeAsync()
    {
        await _app.StopAsync();
        await _app.DisposeAsync();
    }
}

[Collection("server")]
public class ProxyRouteTests(ServerFixture f) : IAsyncLifetime
{
    private Upstream _up = null!;
    private ProxyRouteService Proxy => f.App.Services.GetRequiredService<ProxyRouteService>();

    public async Task InitializeAsync() => _up = await Upstream.StartAsync();
    public async Task DisposeAsync() => await _up.DisposeAsync();

    private SaveProxyRouteRequest Req(string name, ProxyAccess access = ProxyAccess.Anonymous, params int[] ports) => new()
    {
        Name = name,
        PathPrefix = "/" + name,
        Destinations = _up.Url,
        Ports = ports.Length > 0 ? [.. ports] : [f.EnvPorts["Dev"]],
        Access = access,
        Reason = "test",
    };

    private string Dev(string path) => f.Url("Dev", path);

    [Fact]
    public async Task RouteIsServedLiveOnlyOnSelectedPorts()
    {
        await Proxy.CreateAsync(f.Admin, Req("echo", ProxyAccess.Anonymous, f.EnvPorts["Dev"], f.EnvPorts["Test"]), null);
        using var http = f.Client();

        var res = await http.GetAsync(Dev("/echo/hello/world"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        Assert.Equal("upstream path=/hello/world", await res.Content.ReadAsStringAsync()); // prefix stripped

        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(f.Url("Test", "/echo/x"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync(f.Url("Prod", "/echo/x"))).StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync(f.AdminUrl("/echo/x"))).StatusCode);
    }

    [Fact]
    public async Task SignedInRoutesSendPeopleToTheAdminSignIn()
    {
        await Proxy.CreateAsync(f.Admin, Req("private-tool", ProxyAccess.SignedIn), null);
        using var http = f.Client();
        var res = await http.GetAsync(Dev("/private-tool/"));
        Assert.Equal(HttpStatusCode.Redirect, res.StatusCode);
        Assert.Equal($"https://localhost:{f.AdminPort}/Account/Login", res.Headers.Location!.ToString());
    }

    [Fact]
    public async Task DisableEnableAndDeleteApplyImmediately()
    {
        var id = await Proxy.CreateAsync(f.Admin, Req("toggle"), null);
        using var http = f.Client();
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(Dev("/toggle/"))).StatusCode);

        await Proxy.SetEnabledAsync(f.Admin, id, false, "maintenance", null);
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync(Dev("/toggle/"))).StatusCode);

        await Proxy.SetEnabledAsync(f.Admin, id, true, "back", null);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(Dev("/toggle/"))).StatusCode);

        await Proxy.DeleteAsync(f.Admin, id, "retired", null);
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync(Dev("/toggle/"))).StatusCode);

        var (events, _) = await f.Audit.QueryAsync(new AuditQuery(Target: "/toggle"));
        Assert.Contains(events, e => e.Action == "proxy.create" && e.Details!.Contains("reason: test"));
        Assert.Contains(events, e => e.Action == "proxy.disable" && e.Details!.Contains("maintenance"));
        Assert.Contains(events, e => e.Action == "proxy.delete");
    }

    [Fact]
    public async Task UpdateChangesUpstreamBehaviourLive()
    {
        var req = Req("upd");
        var id = await Proxy.CreateAsync(f.Admin, req, null);
        using var http = f.Client();
        Assert.Equal("upstream path=/a", await http.GetStringAsync(Dev("/upd/a")));

        req.StripPrefix = false;
        await Proxy.UpdateAsync(f.Admin, id, req, null);
        Assert.Equal("upstream path=/upd/a", await http.GetStringAsync(Dev("/upd/a")));
    }

    [Fact]
    public async Task AdminPortIsNeverUsedForRoutes()
    {
        // Refused when saving...
        var ex = await Assert.ThrowsAsync<ValidationException>(() => Proxy.CreateAsync(f.Admin, Req("on-admin", ProxyAccess.Anonymous, f.AdminPort), null));
        Assert.Contains("admin port", ex.Message);

        // ...and not served even if a stored route lists it (e.g. created by an older version).
        await Proxy.CreateAsync(f.Admin, Req("legacy-admin"), null);
        await using (var db = await f.DbAsync())
        {
            var row = db.ProxyRoutes.Single(r => r.PathPrefix == "/legacy-admin");
            row.Ports = $"{f.AdminPort},{f.EnvPorts["Dev"]}";
            await db.SaveChangesAsync();
        }
        f.App.Services.GetRequiredService<DbProxyConfigProvider>().Reload();

        using var http = f.Client();
        Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync(f.AdminUrl("/legacy-admin/x"))).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(Dev("/legacy-admin/x"))).StatusCode);
    }

    [Fact]
    public async Task KeyportCredentialsNeverReachTheUpstream()
    {
        await Proxy.CreateAsync(f.Admin, Req("hdr", ProxyAccess.Anonymous), null);
        var apiKey = Keyport.Core.Crypto.ApiKeys.Generate().Plaintext;   // any well-formed Keyport key must be stripped

        using var http = f.Client();
        var withKeys = new HttpRequestMessage(HttpMethod.Get, Dev("/hdr/headers"));
        withKeys.Headers.TryAddWithoutValidation("Cookie", "__Host-kp-auth=SESSION; __Host-kp-af=AF; .AspNetCore.Antiforgery.x=Y; Identity.TwoFactorUserId=Z; theme=dark");
        withKeys.Headers.Authorization = new("Bearer", apiKey);
        withKeys.Headers.Add("X-Api-Key", apiKey);
        var seen = await (await http.SendAsync(withKeys)).Content.ReadFromJsonAsync<Dictionary<string, string>>();
        Assert.Equal("theme=dark", seen!["cookie"]);
        Assert.Equal("", seen["authorization"]);
        Assert.Equal("", seen["x-api-key"]);

        // The upstream's own credentials are passed through untouched.
        var basic = new HttpRequestMessage(HttpMethod.Get, Dev("/hdr/headers"));
        basic.Headers.Authorization = new("Basic", "dXNlcjpwdw==");
        var seenBasic = await (await http.SendAsync(basic)).Content.ReadFromJsonAsync<Dictionary<string, string>>();
        Assert.Equal("Basic dXNlcjpwdw==", seenBasic!["authorization"]);
    }

    [Fact]
    public async Task UpstreamCannotSetKeyportCookies()
    {
        await Proxy.CreateAsync(f.Admin, Req("cookies", ProxyAccess.Anonymous), null);
        using var http = f.Client();
        var res = await http.GetAsync(Dev("/cookies/set-cookies"));
        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
        var set = res.Headers.GetValues("Set-Cookie").ToList();
        Assert.Single(set);
        Assert.StartsWith("upstream-pref=dark", set[0]);
    }

    [Theory]
    [InlineData("secrets", "/secrets", "http://127.0.0.1:1/", "used by Keyport")]
    [InlineData("api-shadow", "/api", "http://127.0.0.1:1/", "used by Keyport")]
    [InlineData("bad-prefix", "/Has Space", "http://127.0.0.1:1/", "Path prefix")]
    [InlineData("metadata", "/meta", "http://169.254.169.254/", "link-local")]
    [InlineData("not-allowed", "/other", "http://10.1.2.3/", "AllowedUpstreams")]
    [InlineData("bad-scheme", "/ftp", "ftp://127.0.0.1/", "http(s)")]
    [InlineData("creds", "/creds", "http://user:pw@localhost/", "credentials")]
    public async Task InvalidRoutesAreRejected(string name, string prefix, string destination, string expected)
    {
        var req = Req(name);
        req.PathPrefix = prefix;
        req.Destinations = destination;
        var ex = await Assert.ThrowsAsync<ValidationException>(() => Proxy.CreateAsync(f.Admin, req, null));
        Assert.Contains(expected, ex.Message);
    }

    [Fact]
    public async Task ReasonPortsAndAdminRoleAreRequired()
    {
        var noReason = Req("no-reason");
        noReason.Reason = null;
        await Assert.ThrowsAsync<ValidationException>(() => Proxy.CreateAsync(f.Admin, noReason, null));

        var badPort = Req("bad-port", ProxyAccess.Anonymous, 12345);
        await Assert.ThrowsAsync<ValidationException>(() => Proxy.CreateAsync(f.Admin, badPort, null));

        var editor = new UserAccess("e", "editor", false, false, new Dictionary<int, EnvironmentRole> { [f.Env("Dev").Id] = EnvironmentRole.Editor });
        await Assert.ThrowsAsync<UnauthorizedAccessException>(() => Proxy.CreateAsync(editor, Req("not-admin"), null));
    }

    [Fact]
    public async Task UpstreamTestReportsReachability()
    {
        var req = Req("probe");
        req.HealthCheckPath = "/healthz";
        var results = await Proxy.TestUpstreamsAsync(f.Admin, req, null);
        Assert.True(results.Single().Success, results.Single().Message);
    }
}

/// <summary>UI-managed routes must survive a restart: they live in the database on the data volume.</summary>
public class ProxyPersistenceTests
{
    [Fact]
    public async Task RoutesPersistAcrossRestart()
    {
        await using var up = await Upstream.StartAsync();
        var f = new ServerFixture();
        await f.InitializeAsync();
        try
        {
            var proxy = f.App.Services.GetRequiredService<ProxyRouteService>();
            await proxy.CreateAsync(f.Admin, new SaveProxyRouteRequest
            {
                Name = "persisted", PathPrefix = "/persisted", Destinations = up.Url, Ports = [f.EnvPorts["Upgrade"], f.EnvPorts["Test"]],
                Access = ProxyAccess.Anonymous, RelaxCsp = true, Reason = "persistence test",
            }, null);
            var disabledId = await proxy.CreateAsync(f.Admin, new SaveProxyRouteRequest
            {
                Name = "parked", PathPrefix = "/parked", Destinations = up.Url, Ports = [f.EnvPorts["Test"]], Access = ProxyAccess.Anonymous, Reason = "x",
            }, null);
            await proxy.SetEnabledAsync(f.Admin, disabledId, false, "parked", null);

            await f.RestartAsync();

            using var http = f.Client();
            var res = await http.GetAsync(f.Url("Upgrade", "/persisted/after-restart"));
            Assert.Equal(HttpStatusCode.OK, res.StatusCode);
            Assert.Equal("upstream path=/after-restart", await res.Content.ReadAsStringAsync());
            Assert.True((await f.App.Services.GetRequiredService<ProxyRouteService>().ListAsync(f.Admin)).Single(r => r.Name == "persisted").RelaxCsp);   // settings restored too
            Assert.Equal(HttpStatusCode.OK, (await http.GetAsync(f.Url("Test", "/persisted/x"))).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync(f.Url("Dev", "/persisted/x"))).StatusCode);
            Assert.Equal(HttpStatusCode.NotFound, (await http.GetAsync(f.Url("Test", "/parked/"))).StatusCode); // disabled stays disabled

            var routes = await f.App.Services.GetRequiredService<ProxyRouteService>().ListAsync(f.Admin);
            Assert.Equal(2, routes.Count);
        }
        finally
        {
            await f.DisposeAsync();
        }
    }
}

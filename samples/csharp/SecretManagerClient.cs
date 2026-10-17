// SecretManager client for .NET 6+ applications. Drop-in replacement for the legacy WCF proxy.
//
// Usage:
//   var sm = new SecretManagerClient(
//       baseUrl: "https://secretmanager.corp.local:9446",   // the PORT selects the environment (9446 = Prod)
//       apiKey: Environment.GetEnvironmentVariable("SM_API_KEY")!,
//       caCertPath: "/etc/ssl/secretmanager-ca.crt");        // optional if the CA is in the OS trust store
//   string cs = await sm.GetConnectionStringAsync("billing/oracle-main");
//   var cred = await sm.GetCredentialAsync("partners/acme-api");
//
// Values are cached in memory for a short time (default 5 min) to avoid a network call per DB connection.
// Never log the returned values.

using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;

namespace SecretManager.Client;

public sealed record ConnectionComponents(string? Host, int? Port, string? Database, string? ServiceName, string? Sid, string? Username, string? Password);
public sealed record ConnectionResult(string Name, string Environment, string Type, string ConnectionString, ConnectionComponents Components, int Version);
public sealed record CredentialResult(string Name, string Environment, string Type, string? Username, string? Password, string? Domain, string? Url, int Version);

public sealed class SecretManagerException(string message, HttpStatusCode? status = null) : Exception(message)
{
    public HttpStatusCode? Status { get; } = status;
}

public sealed class SecretManagerClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly TimeSpan _cacheTtl;
    private readonly ConcurrentDictionary<string, (DateTime Expires, object Value)> _cache = new();

    public SecretManagerClient(string baseUrl, string apiKey, string? caCertPath = null, TimeSpan? cacheTtl = null)
    {
        var handler = new SocketsHttpHandler { PooledConnectionLifetime = TimeSpan.FromMinutes(5) };
        if (caCertPath is not null)
        {
            // Trust ONLY the SecretManager CA for this client (pinning), instead of disabling validation.
            var ca = X509CertificateLoader.LoadCertificateFromFile(caCertPath);
            handler.SslOptions.CertificateChainPolicy = new X509ChainPolicy
            {
                TrustMode = X509ChainTrustMode.CustomRootTrust,
                CustomTrustStore = { ca },
                RevocationMode = X509RevocationMode.NoCheck,
            };
        }

        _http = new HttpClient(handler) { BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/"), Timeout = TimeSpan.FromSeconds(10) };
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd("SecretManagerClient/1.0");
        _cacheTtl = cacheTtl ?? TimeSpan.FromMinutes(5);
    }

    public async Task<string> GetConnectionStringAsync(string name, CancellationToken ct = default) =>
        (await GetConnectionAsync(name, ct)).ConnectionString;

    public Task<ConnectionResult> GetConnectionAsync(string name, CancellationToken ct = default) =>
        GetCachedAsync<ConnectionResult>($"api/v1/connections/{name}", ct);

    public Task<CredentialResult> GetCredentialAsync(string name, CancellationToken ct = default) =>
        GetCachedAsync<CredentialResult>($"api/v1/credentials/{name}", ct);

    /// <summary>Drops cached values, e.g. after a login failure that suggests the password was rotated.</summary>
    public void Invalidate(string? name = null)
    {
        if (name is null) _cache.Clear();
        else foreach (var k in _cache.Keys.Where(k => k.EndsWith("/" + name))) _cache.TryRemove(k, out _);
    }

    private async Task<T> GetCachedAsync<T>(string path, CancellationToken ct)
    {
        if (_cache.TryGetValue(path, out var hit) && hit.Expires > DateTime.UtcNow)
            return (T)hit.Value;

        using var res = await _http.GetAsync(path, ct);
        if (res.StatusCode == HttpStatusCode.Unauthorized)
            throw new SecretManagerException("API key rejected. Check the key, its expiry, and that you are calling the port of the key's environment.", res.StatusCode);
        if (res.StatusCode == HttpStatusCode.NotFound)
            throw new SecretManagerException($"Secret not found or not granted to this client: {path}", res.StatusCode);
        if (!res.IsSuccessStatusCode)
            throw new SecretManagerException($"SecretManager returned {(int)res.StatusCode}.", res.StatusCode);

        var value = await res.Content.ReadFromJsonAsync<T>(cancellationToken: ct) ?? throw new SecretManagerException("Empty response.");
        _cache[path] = (DateTime.UtcNow + _cacheTtl, value!);
        return value;
    }

    public void Dispose() => _http.Dispose();
}

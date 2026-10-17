# Migrating clients from the WCF secrets service

This guide is for application teams moving from the legacy WCF service to SecretManager's REST API. There is no SOAP compatibility endpoint; each client makes a small code change.

## 1. What changes

| | Legacy WCF | SecretManager |
|---|---|---|
| Transport | SOAP over HTTP(S), generated proxy | HTTPS + JSON, any HTTP client |
| Environment selection | Parameter or separate endpoint config | **The port** you call: Dev `9443`, Test `9444`, Upgrade `9445`, Prod `9446` |
| Authentication | (varies) | `Authorization: Bearer sm_<prefix>_<secret>`. One key per application per environment. |
| Authorization | (varies) | The key's **grants**: exact names or `prefix/*` |
| Connection string | Returned as a string | `GET /api/v1/connections/{name}` → `connectionString` plus parsed `components` |
| Username/password | Returned as fields | `GET /api/v1/credentials/{name}` → `username`, `password`, `domain` |
| Errors | SOAP faults | HTTP status: `401` key problem, `404` not found or not granted, `429` rate limited |
| TLS trust | Public or enterprise certificate | SecretManager internal CA (install `secretmanager-ca.crt`) or your enterprise CA if imported |

### Operation mapping

| Typical WCF operation | REST call |
|---|---|
| `GetConnectionString(env, name)` | `GET https://host:<envPort>/api/v1/connections/{name}` → `.connectionString` |
| `GetOracleConnection(env, name)` / `GetSqlConnection(env, name)` | same as above (the type is in the response) |
| `GetCredentials(env, name)` / `GetServiceAccount(env, name)` | `GET https://host:<envPort>/api/v1/credentials/{name}` |
| `ListSecrets(env)` | `GET https://host:<envPort>/api/v1/secrets?prefix=...` (names only) |
| `Ping()` | `GET https://host:<envPort>/api/v1/status` (authenticated) or `/health/ready` (anonymous) |

## 2. Onboarding steps (per application)

1. **Secrets**: an Editor creates each connection or credential in each environment. Name them by application or domain, e.g. `billing/oracle-main`, `billing/partner-api`. Use **Promote** to copy settings forward (Dev → Test → Upgrade → Prod); each environment gets its own password.
2. **API clients**: in **API clients**, create one client per environment, e.g. `billing-service`, with grant `billing/*`. Optionally restrict it to the app servers' CIDRs and set an expiry. Copy the key when shown; it is shown **once**.
3. **Store the key** where the app keeps other secrets: an environment variable (`SM_API_KEY`), a Kubernetes Secret, or an IIS app-pool environment variable / DPAPI-protected config. **Never commit it.**
4. **Trust the CA** on the app hosts (skip this if you use an imported enterprise CA):
   - Windows: `Import-Certificate -FilePath secretmanager-ca.crt -CertStoreLocation Cert:\LocalMachine\Root`
   - Debian/Ubuntu: copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
   - RHEL: copy to `/etc/pki/ca-trust/source/anchors/` and run `update-ca-trust`
   - Or pin it in the client only (see the C# sample's `caCertPath`).
5. **Change the code** (below), deploy to Dev, verify, and promote.
6. **Verify** in SecretManager's **Activity log** (API tab) that the client's requests return 200, and remove the WCF binding from the app's configuration.

## 3. Code

### .NET (Framework 4.8 or .NET 6+)

Copy [`samples/csharp/SecretManagerClient.cs`](../samples/csharp/SecretManagerClient.cs) into the project (.NET 6+; for .NET Framework, replace `SocketsHttpHandler` with `HttpClientHandler`).

```csharp
// Before (WCF)
var proxy = new SecretServiceClient("Prod");
string cs = proxy.GetConnectionString("Prod", "BillingOracle");

// After
var sm = new SecretManagerClient(
    baseUrl: config["SecretManager:Url"],                 // e.g. https://secretmanager.corp.local:9446
    apiKey: Environment.GetEnvironmentVariable("SM_API_KEY")!);
string cs = await sm.GetConnectionStringAsync("billing/oracle-main");
```

Register it once (e.g. `services.AddSingleton(...)`) and reuse it. It caches values for 5 minutes. When a database login fails, call `sm.Invalidate("billing/oracle-main")` and retry once; this handles password rotation gracefully.

### PowerShell

```powershell
$env:SM_API_KEY = '<from your secret store>'
$cs   = ./samples/powershell/Get-SmSecret.ps1 -BaseUrl https://secretmanager.corp.local:9446 -Name billing/sql-main
$cred = ./samples/powershell/Get-SmSecret.ps1 -BaseUrl https://secretmanager.corp.local:9446 -Name batch/svc-account -Kind credentials -AsPSCredential
```

### Shell / anything with curl

```bash
SM_API_KEY=... SM_CA_FILE=./secretmanager-ca.crt \
  ./samples/shell/get-secret.sh https://secretmanager.corp.local:9443 connections billing/sql-main
```

### Java / Python / others

Any HTTP client works: send `GET` with the `Authorization: Bearer` header to the environment's port, and parse JSON.

```python
import requests
r = requests.get("https://secretmanager.corp.local:9444/api/v1/credentials/billing/partner-api",
                 headers={"Authorization": f"Bearer {key}"}, verify="secretmanager-ca.crt", timeout=10)
r.raise_for_status(); cred = r.json()
```

## 4. Rollout plan (suggested)

| Phase | Scope | Exit criteria |
|---|---|---|
| 0. Stand-up | Deploy SecretManager; admins enrolled; CA distributed; firewall rules per port | Health green; the CA is trusted from each environment's network |
| 1. Pilot | 1–2 apps in Dev and Test | Apps read from SecretManager; WCF unused by them (check WCF logs) |
| 2. Wave rollout | Remaining apps, Dev → Test → Upgrade | Activity log shows only 200s per client; no 401/404 |
| 3. Prod | Apps switch in their normal release windows | All apps on SecretManager in Prod |
| 4. Decommission | Disable the WCF endpoint, then remove it; rotate every credential the WCF service ever held | WCF off; credentials rotated |

**Rotate credentials after migration.** Values copied from the legacy system should be considered exposed to it. Rotate them in the database, then update them in SecretManager (which creates a new version that clients pick up within their cache TTL).

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `401 Invalid or missing API key for this environment.` | Wrong environment port for this key (most common), or the key is expired, disabled or rotated, or the source IP is not in the allow-list. An admin can see the exact reason in the **Audit trail** (`api.authenticate`). |
| `404 Secret not found.` | The name doesn't exist **in this environment**, or the client's grants don't cover it. Check **Compare environments** and the client's grants. |
| `400 … use /api/v1/secrets/...` | Wrong endpoint for the type (e.g. a basic-auth secret requested from `/connections`) |
| `429` | More than 300 requests/min with one key. Cache values in the client. |
| TLS error / `UntrustedRoot` | Install or pin the SecretManager CA, and check that the host name you call is in the certificate SANs (Certificates page). |
| `connection refused` | The port is not open from your network (firewall), or the environment is not configured. |

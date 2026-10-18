<p align="center">
  <img src="docs/banner.svg" alt="Keyport Banner" width="100%">
</p>

<p align="center">
  <a href="https://github.com/jmconlon2001/keyport/actions/workflows/ci.yml"><img src="https://github.com/jmconlon2001/keyport/actions/workflows/ci.yml/badge.svg?branch=main" alt="Build Status"></a>
  <a href="https://github.com/jmconlon2001/keyport/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square" alt="License"></a>
  <a href="https://github.com/jmconlon2001/keyport"><img src="https://img.shields.io/badge/deepspace-enabled-purple?style=flat-square" alt="Theme"></a>
</p>

---

A self-contained, containerized service that stores and serves **database connection strings (Oracle and SQL Server)** and **credentials (basic auth and service accounts)**, replacing the legacy WCF service.

- REST API over HTTPS with per-application API keys.
- **Every environment (Dev, Test, Upgrade, Prod) is served on its own port**, and a key works only on its own environment's port.
- Web UI to manage connections, passwords, API clients and users.
- Built-in edge/reverse proxy and an **internal certificate authority with automatic TLS** (issue, renew, hot-swap).
- Envelope encryption at rest, mandatory MFA, a tamper-evident audit trail, and a full API/UI activity log with configurable retention.
- Status and health pages and APIs.
- One container, one volume, one secret (the master key).

<p align="center">
  <img src="docs/images/02-dashboard-dark.png" alt="Keyport dashboard" width="900">
</p>

<p align="center"><em>Shown with the built-in demo data for the fictional company "Nimbus Orbital". Try it yourself with <code>--seed-demo</code> (see <a href="#103-try-it-with-demo-data">10.3</a>).</em></p>

### Tour

| | |
|---|---|
| **Add a secret: guided, plain language, nothing to memorise**<br>![New secret](docs/images/06-new-secret.png) | **Every secret: who can read it, what they receive, full history**<br>![Secret detail](docs/images/05-secret-detail.png) |
| **Give an application access by picking from what exists**<br>![Grant picker](docs/images/09-grant-picker.png) | **Applications, with key age at a glance**<br>![Applications](docs/images/08-applications.png) |
| **Protected Prod, colour-coded environments**<br>![Prod secrets](docs/images/04-secrets-prod.png) | **Spot gaps before a release**<br>![Compare environments](docs/images/07-compare.png) |
| **Live status: traffic, errors and latency per environment port**<br>![Status](docs/images/10-status.png) | **Health checks at a glance**<br>![Health](docs/images/11-health.png) |
| **Every API call and UI action, logged**<br>![Activity log](docs/images/12-activity.png) | **Tamper-evident audit trail with one-click verification**<br>![Audit trail](docs/images/13-audit.png) |
| **Per-environment access for every person**<br>![Users](docs/images/14-users.png) | **Built-in reverse proxy, managed in the UI**<br>![Reverse proxy](docs/images/15-reverse-proxy.png) |
| **Automatic TLS from the built-in CA**<br>![Certificates](docs/images/16-certificates.png) | **A help guide written for non-technical users**<br>![Help](docs/images/17-help.png) |
| **Light theme**<br>![Dashboard light](docs/images/03-dashboard-light.png) | **Sign-in with mandatory MFA or passkeys**<br>![Sign in](docs/images/01-sign-in.png) |

**On your phone too**

<p align="center">
  <img src="docs/images/18-mobile-dashboard.png" alt="Mobile dashboard" width="240">&nbsp;&nbsp;
  <img src="docs/images/19-mobile-secrets.png" alt="Mobile secrets" width="240">&nbsp;&nbsp;
  <img src="docs/images/20-mobile-menu.png" alt="Mobile navigation" width="240">
</p>

> This document is written for architects and reviewers. It explains what was built, how it works, why it was built that way, and its known limits. Day-to-day client onboarding is in [docs/client-migration.md](docs/client-migration.md).

---

## Contents

1. [At a glance](#1-at-a-glance)
2. [Architecture](#2-architecture)
3. [Environment segmentation by port](#3-environment-segmentation-by-port)
4. [Security model](#4-security-model)
5. [Logging, audit and observability](#5-logging-audit-and-observability)
6. [Data model and storage](#6-data-model-and-storage)
7. [REST API reference](#7-rest-api-reference)
8. [User interface](#8-user-interface)
9. [Configuration reference](#9-configuration-reference)
10. [Deployment and operations](#10-deployment-and-operations)
11. [Migrating from the WCF service](#11-migrating-from-the-wcf-service)
12. [Development and testing](#12-development-and-testing)
13. [Design decisions](#13-design-decisions)
14. [Known limitations and roadmap](#14-known-limitations-and-roadmap)

---

## 1. At a glance

| Concern | Implementation |
|---|---|
| Runtime | .NET 10 (LTS), ASP.NET Core, Kestrel; single process |
| UI | Blazor (interactive server rendering), Bootstrap 5.3 + custom design system, light/dark, responsive (desktop first, works on phones) |
| Storage | SQLite (WAL) on a mounted volume, `/data/keyport.db` |
| Encryption at rest | AES-256-GCM envelope encryption: a random data key (DEK) per secret version, wrapped by a 256-bit master key (KEK) |
| Master key | File supplied as a container secret (`/run/secrets/keyport_master_key`); never stored by the app |
| TLS | Built-in internal CA (ECDSA P-384 root, 10 years). The server certificate (ECDSA P-256, 90 days) auto-renews at two-thirds of its lifetime with zero downtime. An enterprise CA can be imported instead. |
| Edge / reverse proxy | In-process Kestrel edge: TLS termination, port-to-environment binding, security headers, rate limiting, request limits. **Reverse-proxy routes managed in the UI** (YARP): applied live, stored in the database, persisted across restarts; plus optional routes from configuration. |
| Environments | Dev :9443 · Test :9444 · Upgrade :9445 · Prod :9446 (configurable; add or remove environments without code changes) |
| Human auth | Local accounts (ASP.NET Core Identity). **MFA is mandatory** (TOTP authenticator or passkey/WebAuthn), plus lockout and a forced password change on first sign-in. |
| Machine auth | API keys `kp_<prefix>_<secret>` (256-bit). Stored as SHA-256. Each key is bound to one environment, with grants chosen from existing secrets and an optional CIDR allow-list. **Keys never expire by default** (an expiry date is optional). The **key's age** is shown everywhere, and keys over a year old are flagged. |
| Authorization | Global roles Admin and Auditor; per-environment roles Viewer and Editor. **Protected environments** (Upgrade, Prod) require a reason for every reveal or change. |
| Audit | Append-only, SHA-256 hash-chained audit trail of every security event. Verified hourly and on demand. |
| Activity log | Every API request and every UI request or action, with status and latency. Retention is configurable per source. |
| Health / status | `/health`, `/health/live`, `/health/ready` on every port; `/admin/api/status` and `/api/v1/status`; Status and Health pages in the UI |
| Container | Distroless (chiseled) Ubuntu image, non-root UID 1654, read-only root filesystem, all capabilities dropped, no shell, built-in health check. Works with Podman and Docker. |
| Tests | 109 automated tests (unit, plus integration tests that run the real server with real TLS on random ports) plus a scripted headless-browser end-to-end run |

---

## 2. Architecture

### 2.1 Deployment view

```mermaid
flowchart LR
    subgraph Clients
        A1[Apps in Dev]:::dev
        A2[Apps in Test]:::test
        A3[Apps in Upgrade]:::upg
        A4[Apps in Prod]:::prod
        U[Administrators / users<br/>browser]
    end

    subgraph Container["keyport container (non-root, read-only FS)"]
        direction TB
        H[":8080 HTTP<br/>bootstrap"]
        ADM[":8443 HTTPS<br/>Admin UI + admin API"]
        D[":9443 HTTPS Dev API"]:::dev
        T[":9444 HTTPS Test API"]:::test
        G[":9445 HTTPS Upgrade API"]:::upg
        P[":9446 HTTPS Prod API"]:::prod
        EDGE{{"Edge pipeline<br/>TLS · port gate · headers ·<br/>rate limit · activity log"}}
        APP["Application services<br/>Secrets · Clients · Users · Audit · CA"]
        CA["Internal CA<br/>cert issue / renew / hot-swap"]
        H & ADM & D & T & G & P --> EDGE --> APP
        APP --- CA
    end

    VOL[("/data volume<br/>SQLite · CA keys (encrypted) ·<br/>data-protection keys (encrypted)")]
    KEK[["/run/secrets/keyport_master_key<br/>(container secret)"]]

    A1 -->|"Bearer key (Dev)"| D
    A2 --> T
    A3 --> G
    A4 --> P
    U --> ADM
    U -. "first time: GET /ca.crt" .-> H
    APP --- VOL
    KEK -. read at startup .-> APP

    classDef dev fill:#d1fae5,stroke:#10b981,color:#064e3b
    classDef test fill:#dbeafe,stroke:#3b82f6,color:#1e3a8a
    classDef upg fill:#fef3c7,stroke:#f59e0b,color:#78350f
    classDef prod fill:#fee2e2,stroke:#ef4444,color:#7f1d1d
```

In a typical enterprise network, the per-environment ports are opened only from that environment's network segments (firewall or security groups). This gives **network-level** isolation on top of the **application-level** isolation described in §3. For stronger separation, each environment can bind to a different NIC or IP (`Environments[].BindAddress`).

### 2.2 Component view (source layout)

```
Keyport.sln
├── src/Keyport.Core/              Pure logic, no web dependencies
│   ├── Crypto/  MasterKey · EnvelopeEncryptor · ApiKeys · PasswordGenerator
│   ├── Pki/     CertificateAuthority (create root, issue/renew server certs)
│   ├── Secrets/ SecretType · SecretMetadata · SecretPayload · ConnectionStringFactory · SecretNames (grants)
│   └── Audit/   AuditChain (hash-chain computation/verification)
├── src/Keyport.Server/            ASP.NET Core host
│   ├── KeyportApp.cs              Composition root: DI, Kestrel listeners, auth, pipeline, startup
│   ├── Cli.cs                           --healthcheck · --generate-master-key · --rotate-kek
│   ├── Configuration/                   Strongly-typed options
│   ├── Edge/                            PortGate · SecurityHeaders · ActivityLogging · KEK XML encryptor
│   ├── Api/                             SecretsApi (/api/v1) · AdminApi (/admin/api)
│   ├── Services/                        SecretService · ApiClientService · UserAdminService · AuditService · ProxyRouteService (+DbProxyConfigProvider) ·
│   │                                    ActivityLogger (+writer, retention) · CertificateManager (+renewal) ·
│   │                                    EnvironmentRegistry · AccessService · Health checks · StatusService ·
│   │                                    ConnectionTester
│   ├── Data/                            EF Core DbContext, entities, migrations
│   ├── Components/                      Blazor UI (Layout, Pages, Shared, Account/Identity pages)
│   └── wwwroot/                         app.css design system, icons (inline SVG), JS helpers
├── tests/Keyport.Tests/           xUnit unit + integration tests
├── samples/                             C# client, PowerShell, shell
├── docs/                                Migration guide, screenshots (docs/images), brand assets: logo.svg (mark + wordmark),
                                     logo-mark.svg (mark only), banner.svg; app icon/favicon in wwwroot/img/logo-mark.svg
├── Dockerfile · compose.yaml
```

`Keyport.Core` has no dependency on ASP.NET. The cryptography, CA, connection-string and audit-chain logic can be reviewed and tested in isolation.

### 2.3 Request flow: an application reads a connection string

```mermaid
sequenceDiagram
    autonumber
    participant App as App (Prod)
    participant K as Kestrel :9446 (TLS)
    participant Gate as PortGate
    participant RL as Rate limiter
    participant F as ApiKeyFilter
    participant S as SecretService
    participant DB as SQLite
    participant Au as AuditService
    participant Act as ActivityLogger

    App->>K: GET /api/v1/connections/billing/oracle-main<br/>Authorization: Bearer sm_ab12cd34_…
    K->>Gate: socket LocalPort = 9446 → listener = Prod
    Gate-->>Gate: path must be /api/v1/* (UI/admin → 404)
    Gate->>RL: per-key fixed window (default 300/min)
    RL->>F: authenticate
    F->>DB: lookup client by prefix, constant-time hash compare
    F-->>F: key env == port env? enabled? not expired? source IP in CIDR?
    alt any check fails
        F->>Au: api.authenticate · Denied · reason
        F-->>App: 401 (generic message)
    end
    F->>S: resolve(Prod, "billing/oracle-main") if granted
    S->>DB: current SecretVersion
    S-->>S: unwrap DEK with KEK, decrypt (AAD = secret|id|env|version)
    S->>Au: api.read-connection · Success · v3
    S-->>App: 200 {connectionString, components, version}<br/>Cache-Control: no-store
    K->>Act: queue activity row (client, env, path, status, latency)
```

### 2.4 Startup sequence

1. Load and validate configuration. Startup fails on duplicate ports or names, or no environments.
2. **Load the master key**. Startup fails if it is missing or malformed.
3. Run database migrations, then enable WAL.
4. **Key check**: if any stored secret was encrypted under a different master key ID, refuse to start. This prevents silently serving undecryptable data, or overwriting with a wrong key.
5. Sync environments from configuration into the database. Removed environments are deactivated, not deleted.
6. Seed roles. On first run, create the `admin` user with a random 20-character password and print it once to the log.
7. Initialize the CA: load or create the root, and load or (re)issue the server certificate if it is missing, due for renewal, has changed SANs, or does not chain to the current CA.
8. Start the listeners and background jobs: certificate renewal (hourly), audit-chain verification (hourly), activity-log writer, retention purge (daily).

---

## 3. Environment segmentation by port

Segmentation is enforced in several independent layers, so a single mistake does not expose another environment's secrets.

| # | Layer | What it does | Where |
|---|---|---|---|
| 1 | **Network** | Each environment has its own TCP port (and optionally its own bind address). Firewalls can admit only the matching network segments. | Kestrel listeners, `Environments[].Port/BindAddress` |
| 2 | **Listener identity** | The environment is derived from the **socket's local port**, never from `Host`, `X-Forwarded-*` or any other client-controlled header. | `PortGateMiddleware` |
| 3 | **Route gate** | Env ports serve **only** `/api/v1/*` and `/health*`. The admin port never serves `/api/v1`. The HTTP port serves only `/ca.crt` and `/health*` and redirects everything else. Anything else returns **404**. | `PortGateMiddleware` |
| 4 | **Key binding** | Every API key belongs to exactly one environment. A valid Dev key presented on the Prod port returns **401**, and the attempt is audited (`api.authenticate`, "key belongs to Dev, presented on Prod port"). | `ApiClientService.AuthenticateAsync` |
| 5 | **Data scoping** | Lookups are always `WHERE EnvironmentId = <port's env>`. Names are unique per environment, so `billing/sql` in Dev and Prod are different rows with different values. | `SecretService.ResolveAsync` |
| 6 | **Cryptographic binding** | Each ciphertext's AAD includes the environment ID. Copying a Prod ciphertext into a Dev row (for example by direct DB tampering) fails authentication instead of decrypting. | `SecretVersion.Aad` |
| 7 | **Human access** | UI users get Viewer or Editor per environment. A Dev Editor cannot list, view or reveal Prod secrets. | `UserAccess`, `SecretService` |
| 8 | **Promotion without copying credentials** | "Promote" copies name, type, settings and username to the next environment but **never the password**. Prod credentials are always entered separately. | `SecretService.PreparePromotionAsync` |

The integration test `EveryKeyIsRejectedOnEveryOtherEnvironmentPort` tests all 16 key-environment/port combinations against the real server over TLS.

---

## 4. Security model

### 4.1 Threats and mitigations

| Threat | Mitigation |
|---|---|
| Theft of the data volume or a database backup | All secret values are AES-256-GCM encrypted under per-version DEKs wrapped by the KEK, which is **not** on the volume. CA private keys and ASP.NET data-protection keys (which protect auth cookies) are also KEK-encrypted. |
| Database tampering (swap or replay ciphertexts) | AEAD with AAD `secret|{id}|{env}|{version}`. Moved, replayed or altered ciphertexts fail to decrypt. Tested in `CiphertextIsBoundToItsRow`. |
| Editing or deleting audit records | SHA-256 hash chain with dense IDs; any edit or gap breaks verification. Verified hourly (health check) and on demand. See §5.1 for limits. |
| Cross-environment access by an app | §3 layers 1–6 |
| Stolen API key | Scoped to one environment and to explicit grant patterns. Optional source-CIDR allow-list and expiry. Instant rotation or disable. Every use is logged with source IP. Rate limited. |
| API key leakage from the server | Only SHA-256(key) is stored. The plaintext is shown once at creation or rotation. |
| Brute force against API keys | 256-bit random secret. Lookup by public prefix plus constant-time compare. Rate limiting. Failures audited. |
| Phishing or credential stuffing of users | Mandatory MFA (TOTP or passkey). Lockout after 5 failures (15 min). Login rate limit of 10/min/IP. Minimum 12-character passwords. |
| Session theft | `__Host-` cookies (Secure, HttpOnly, SameSite=Strict, host-only), 8 h sliding expiry. Security stamp re-validated every minute, so disabling a user or changing roles takes effect within 60 s. |
| XSS / clickjacking / CSRF | Strict CSP (`script-src 'self'`, no inline scripts, no third-party origins), `X-Frame-Options: DENY`, `frame-ancestors 'none'`, antiforgery tokens on all forms, SameSite=Strict |
| Downgrade / MITM | HTTPS only for every authenticated surface; TLS 1.2/1.3 only; HSTS. HTTP :8080 serves only the public CA certificate and health. |
| Open redirect | The HTTP→HTTPS redirect only targets configured host names, never an arbitrary `Host` header. |
| Proxy routes abused for SSRF or to expose services | Admin-only, reason required, audited. Ports must be chosen explicitly (404 elsewhere). Link-local and cloud-metadata upstreams are always refused. An optional **configuration-only** allow-list (`Proxy:AllowedUpstreams`) restricts upstream hosts. Paths owned by Keyport cannot be shadowed. |
| Shoulder-surfing / over-exposure in the UI | Values are masked by default. Reveal needs a confirmation (and a reason in protected environments), auto-hides after 30 s, and is audited. Copy-to-clipboard is audited. |
| Insider misuse | Per-environment least privilege. Protected-environment reasons are captured in the audit trail. Auditor role for read-only oversight. Every UI page view and action is in the activity log. |
| Container escape / lateral movement | Distroless image (no shell or package manager), non-root, read-only root FS, `cap_drop: ALL`, `no-new-privileges` |
| Formula injection in CSV exports | Cells beginning with `= + - @` are neutralized |

### 4.2 Cryptography

**Envelope encryption** (`Core/Crypto/EnvelopeEncryptor.cs`):

```
DEK        = random 256 bits (per secret version)
ciphertext = nonce(12) ‖ AES-256-GCM(DEK, payloadJson, aad=AAD) ‖ tag(16)
wrappedDek = nonce(12) ‖ AES-256-GCM(KEK, DEK, aad="sm-dek-wrap-v1|"+AAD) ‖ tag(16)
AAD        = "secret|{secretId}|{environmentId}|{version}"
```

- The **payload** (username, password, generic value, optional verbatim connection-string override) is encrypted as one JSON blob per version.
- **Metadata** (host, port, database, service name, options, description, tags) is stored in clear so it can be searched, compared across environments and promoted. It contains no credentials.
- Every row stores the **KeyId** of the KEK that wrapped it: the first 16 hex characters of SHA-256 over a domain-separation label plus the key. This detects key mismatches without revealing the key.
- DEKs are zeroed after use. Nonces are 96-bit random values; each DEK encrypts exactly one message, so nonce reuse cannot occur.

**Master key (KEK)**:
- 32 bytes, supplied as a file: raw bytes, 64 hex characters, or base64. Generate with `openssl rand -base64 32` or `dotnet Keyport.Server.dll --generate-master-key`.
- Read from `/run/secrets/keyport_master_key` (container secret) or `KEYPORT_MASTER_KEY_FILE`.
- **Back it up separately from the data volume.** Without it, nothing can be decrypted. That is the point.

**KEK rotation** (offline, a few seconds): stop the service, then run

```bash
podman run --rm -v keyport-data:/data \
  -v ./secrets/keyport_master_key:/run/secrets/keyport_master_key:ro \
  -v ./secrets/keyport_master_key.new:/new.key:ro \
  localhost/keyport:latest --rotate-kek /new.key
```

This re-wraps every DEK, both CA private keys and all data-protection keys under the new KEK in one transaction. The ciphertexts themselves are untouched. The old key files are backed up to `/data/kek-rotation-backup-<timestamp>` first, and a `kek.rotate` audit event is written. Then replace the secret file with the new key and **recreate** the container. The secret is a bind mount, so a stopped container keeps pointing at the old file:

```bash
mv secrets/keyport_master_key secrets/keyport_master_key.old && mv secrets/keyport_master_key.new secrets/keyport_master_key
podman compose up -d --force-recreate
```

Starting with the old key afterwards is refused ("encrypted with master key(s) … Refusing to start"), and the process exits with code 1. This procedure was verified end to end on the container: the API returned 200 for the same secret before and after rotation, and the old key was rejected.

**API keys**: `kp_` + 8-character public prefix (lookup) + `_` + 43 characters from a 62-symbol alphabet (about 256 bits). Stored as SHA-256 hex. A slow hash is unnecessary because the input is not guessable.

**Generated passwords**: CSPRNG; at least one upper, lower, digit and symbol; symbols limited to characters that never need escaping in connection strings (no `; = ' " { }` or space).

### 4.3 TLS and the internal CA

```mermaid
flowchart LR
    R["Root CA<br/>ECDSA P-384 · 10 yrs · pathLen=0<br/>/data/ca/root.crt + root.key.enc (KEK-encrypted)"]
    S["Server certificate<br/>ECDSA P-256 · 90 days · SAN = HostNames + IpAddresses<br/>/data/ca/server.crt + server.key.enc"]
    R -- signs --> S
    S -- "hot-swapped via ServerCertificateSelector" --> L[":8443 :9443 :9444 :9445 :9446"]
```

- **Automatic**: issued on first start; re-issued at startup if the SANs change. A background job checks hourly and **renews at two-thirds of its lifetime** (day 60 of 90). New handshakes use the new certificate immediately; open connections are unaffected and no restart is needed. Admins can force a renewal from the Certificates page.
- **Trust distribution**: clients trust the root once. It can be downloaded from `http://<host>:8080/ca.crt` (bootstrap) or from the Certificates page. **Verify its SHA-256 fingerprint**, which is printed in the startup log and shown in the UI, before installing.
- **Enterprise CA**: set `Ca:ImportPfxPath` (+ `ImportPfxPasswordFile`) to issue from an existing enterprise intermediate CA (RSA or ECDSA) that clients already trust. The service then never generates its own root.
- Leaf certificates never outlive their issuer. TLS 1.2 and 1.3 only.

### 4.4 Authentication

**Users (admin UI, port 8443)**: ASP.NET Core Identity with local accounts.

| Control | Setting |
|---|---|
| Password policy | ≥ 12 characters, upper, lower, digit, symbol, ≥ 6 unique characters |
| Lockout | 5 failed attempts → 15 minutes. Admins can unlock. |
| MFA | **Mandatory.** Users without an authenticator app or passkey are redirected to enrol before any page loads (`AccountEnforcementMiddleware`). TOTP is shown as a QR code rendered on the server (no third-party JS); recovery codes are issued on enrolment. Passkeys (WebAuthn) are supported for phishing-resistant sign-in. |
| First sign-in | Admin-created and reset accounts get a random temporary password (shown once) and **must** change it before doing anything else. |
| Self-registration / password reset by email | Disabled. Accounts are created and reset by Admins only. |
| Sessions | 8 h sliding. Security stamp re-validated every 60 s. Role or environment changes, disable and MFA reset all rotate the stamp, which ends existing sessions. |

**Applications (env ports)**: `Authorization: Bearer sm_…` (or `X-Api-Key`). A key is accepted only if **all** of these hold:

1. The format is valid and the prefix exists.
2. The hash matches (constant-time comparison).
3. The client belongs to the port's environment.
4. The client is not disabled.
5. The client has not expired.
6. The source IP is in the allow-list (if one is set).

Failure responses are deliberately generic (`401 Invalid or missing API key for this environment.`); the specific reason goes only to the audit trail.

### 4.5 Authorization

| Capability | Admin | Auditor | Editor (per env) | Viewer (per env) |
|---|:-:|:-:|:-:|:-:|
| List and view secret metadata | all envs | – | ✓ | ✓ |
| Reveal or copy secret values (audited) | all envs | – | ✓ | ✓ |
| Create, update, rollback or delete secrets | all envs | – | ✓ | – |
| Promote to the next environment | ✓ | – | needs Editor on the target | – |
| Manage API clients (create, rotate, disable, delete) | all envs | – | ✓ | view |
| Test database connections | ✓ | – | ✓ | ✓ (using stored values) |
| Audit trail and activity log (view, export, verify) | ✓ | ✓ | – | – |
| Users and roles, certificates | ✓ | – | – | – |
| Status and health pages | ✓ | ✓ | ✓ | ✓ |

Authorization is enforced inside the services (`SecretService`, `ApiClientService`, `UserAdminService`), not only by hiding UI elements, so a crafted SignalR call cannot bypass it. The integration test `EnvironmentScopedUsersCannotCrossEnvironments` covers this.

**Protected environments** (Upgrade and Prod by default; `Environments[].Protected`): every reveal, create, update, rollback, delete and client change requires a free-text **reason** (e.g. a change ticket), which is stored in the audit trail. The UI shows a warning banner.

### 4.6 Web and container hardening

- **Headers**:
  - All responses: `Content-Security-Policy` (admin port), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Resource-Policy`, HSTS on HTTPS.
  - The `Server` header is removed.
  - Secret and API responses also get `Cache-Control: no-store`.
- **Limits**: request body ≤ 1 MB, headers ≤ 32 KB, API rate limit per key (default 300/min, `429` when exceeded), login rate limit 10/min/IP.
- **No third-party assets**: icons are inline SVG masks in `app.css`, and Bootstrap is vendored. The UI works fully offline and the CSP allows only `'self'`.
- **Container**: `mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra` (distroless; `-extra` adds ICU/tzdata, which SqlClient needs), UID 1654, `read_only: true`, `tmpfs: /tmp`, `cap_drop: [ALL]`, `no-new-privileges`. The image is about 230 MB.

---

## 5. Logging, audit and observability

There are **two complementary logs**, both viewable in the UI, queryable through the admin API, and exportable to CSV:

| | **Audit trail** | **Activity log** |
|---|---|---|
| Purpose | Security record: who did what to which secret | Operational record: every request and action |
| Contents | Sign-in/out (success, failure, lockout), MFA and passkey changes, password changes, every reveal and copy, create, update, rollback, delete, promotion, client create/rotate/disable/delete, user and role changes, certificate renewals, KEK rotation, exports, log purges, **every secret read by an API client** (granted, denied, not found), every rejected API authentication with its reason | **Every API request** (client or key prefix, environment, method, path, secret name, status, latency, IP, user agent, error reason) and **every UI request and action** (page views, downloads, button actions such as reveal, copy, generate, save, plus validation and permission failures) |
| Integrity | SHA-256 hash chain, verified hourly and on demand | Not chained (high volume) |
| Retention | `Logs:AuditRetentionDays` (default **0 = forever**) | `Logs:ApiLogRetentionDays` (default 90) and `Logs:UiLogRetentionDays` (default 90), configured separately |
| UI | **Audit trail** page (filters, verify, export) | **Activity log** page (API / UI / All tabs, filters, export) |
| API | `GET /admin/api/audit`, `/audit/verify`, `/audit/export.csv` | `GET /admin/api/activity`, `/activity/export.csv` |

### 5.1 Audit hash chain

Each event stores `PrevHash` and `Hash = SHA-256(len:field| … )` over: the previous hash, ID, timestamp ticks, actor, action, environment, target, result, client IP and details. Every field is length-prefixed, so values cannot be shifted between fields. IDs are dense, so a deleted row shows up as a gap.

- **Verification** runs hourly (`AuditIntegrityMonitor` → `audit-chain` health check turns *Unhealthy* on a break) and on demand from the UI or `/admin/api/audit/verify`.
- **Retention without breaking the chain**: purging old events stores the last purged event's `{id, hash}` as an *anchor*. Verification then starts from the anchor.
- **Limit**: a hash chain proves the integrity of the records that remain. It cannot by itself prove that the newest records were not truncated by someone with direct database write access. Mitigation: export to your SIEM or WORM storage on a schedule (CSV export or the admin API). See §14.

### 5.2 Activity log pipeline

Requests are queued in a bounded in-memory channel (50,000 entries) and written in batches every 250 ms by a background writer, so logging never adds database latency to a request. If the queue ever overflows, the drop counter is shown on the Status page and the `background-jobs` health check turns *Degraded*. On shutdown the queue is drained.

### 5.3 Health

Available on **every port**, unauthenticated, and containing no secrets:

| Endpoint | Use | Checks |
|---|---|---|
| `GET /health/live` | Liveness (process up) | none |
| `GET /health/ready` | Readiness | database, master-key, certificates |
| `GET /health` | Full JSON report (200 when Healthy or Degraded, 503 when Unhealthy) | database, master-key (loaded key matches stored data), certificates (expiry of server cert and CA), disk-space (data volume), audit-chain (last verification), background-jobs (renewal, verification, retention, activity queue) |

The container `HEALTHCHECK` calls `dotnet Keyport.Server.dll --healthcheck`, which probes `/health/live`; the distroless image has no curl.

### 5.4 Status

The **Status page** (refreshes every 10 s) and `GET /admin/api/status` (JSON) show:

- version, uptime and database size
- for each listener: port, secret and client counts, requests and errors over 24 h, p50/p95/p99 latency since start, last request time
- certificate expiry, CA fingerprint and master-key ID
- the state of each background job
- the configured retention settings

Applications can call `GET /api/v1/status` on their environment port to confirm connectivity, their key's expiry and their grants.

### 5.5 Process logs

Standard ASP.NET Core console logging goes to stdout (`podman logs keyport`). Secret values are never written to process logs. Driver error messages from "test connection" have the password scrubbed.

---

## 6. Data model and storage

```mermaid
erDiagram
    EnvironmentDef ||--o{ Secret : contains
    Secret ||--|{ SecretVersion : "has versions"
    EnvironmentDef ||--o{ ApiClient : "issues keys for"
    ApiClient ||--o{ ApiClientGrant : "may read"
    AspNetUsers ||--o{ UserEnvironmentRole : "has access to"
    EnvironmentDef ||--o{ UserEnvironmentRole : ""

    EnvironmentDef { int Id string Name int Port string Color bool Protected int SortOrder bool Active }
    Secret { int Id int EnvironmentId string Name "unique per env" string Type string MetadataJson "clear, no credentials" string Tags int CurrentVersion datetime RotateAfterUtc }
    SecretVersion { int Id int SecretId int Version blob WrappedDek blob Ciphertext string KeyId string CreatedBy string Comment }
    ApiClient { int Id int EnvironmentId string Name string KeyPrefix "unique" string KeyHash "SHA-256" string AllowedCidrs datetime ExpiresUtc bool Disabled datetime LastUsedUtc }
    ApiClientGrant { int Id int ApiClientId string Pattern "name | prefix/* | *" }
    UserEnvironmentRole { int Id string UserId int EnvironmentId string Role "Viewer|Editor" }
    AuditEvent { long Id "dense" datetime TimestampUtc string Actor string Action string Environment string Target string Result string ClientIp string Details string PrevHash string Hash }
    ProxyRoute { int Id string Name string PathPrefix string Destinations string Ports string Access bool StripPrefix bool RelaxCsp string LoadBalancing string HealthCheckPath bool Enabled }
    ActivityLog { long Id datetime TimestampUtc string Source "Api|Ui" string Environment string Actor string Method string Path string Target int StatusCode double DurationMs string ClientIp string Error }
```

Plus the standard ASP.NET Core Identity tables (schema v3, including passkeys) and `AppSettings` (audit anchor).

**Secret types and their fields**

| Type | Clear metadata | Encrypted payload | Served by |
|---|---|---|---|
| `OracleConnection` | host, port (1521), service name **or** SID, EZConnect/TNS descriptor toggle, extra driver options | username, password, optional verbatim override | `/connections`, `/credentials`, `/secrets` |
| `SqlServerConnection` | server, port, database, Encrypt (Mandatory/Strict/Optional), TrustServerCertificate, Integrated Security, Application Name, extra options | username, password, optional verbatim override | `/connections`, `/credentials`, `/secrets` |
| `BasicAuth` | endpoint URL, description | username, password | `/credentials`, `/secrets` |
| `ServiceAccount` | domain, "used by", description | username, password | `/credentials`, `/secrets` |
| `Generic` | description | value | `/secrets` |

Connection strings are built by the drivers' own builders (`SqlConnectionStringBuilder`, `OracleConnectionStringBuilder`), so passwords containing `;`, `=` or quotes are escaped correctly. Values are validated on save by round-tripping them through the driver parser.

**Versioning**: changing values always creates a new version; old versions are kept. Rollback copies an old version forward as a new version, so history is never rewritten. Changing only metadata does not create a version.

**Files on the `/data` volume**

| Path | Content | Protection |
|---|---|---|
| `keyport.db` (+ `-wal`, `-shm`) | All data | Secret values KEK-encrypted |
| `ca/root.crt`, `ca/server.crt` | Public certificates | Public |
| `ca/root.key.enc`, `ca/server.key.enc` | CA and server private keys | KEK-encrypted (JSON envelope) |
| `dp-keys/*.xml` | ASP.NET data-protection key ring (cookies, antiforgery) | KEK-encrypted via `KekXmlEncryptor` |

---

## 7. REST API reference

**Base URL**: `https://<host>:<environment port>/api/v1`. The port selects the environment.
**Auth**: `Authorization: Bearer kp_<prefix>_<secret>` (or `X-Api-Key: …`).
**Format**: JSON (camelCase). All responses carry `Cache-Control: no-store`.
**OpenAPI**: `https://<host>:8443/openapi/v1.json` (signed-in users).

| Method | Path | Description |
|---|---|---|
| GET | `/connections/{name}` | Connection string plus components, for Oracle or SQL Server secrets |
| GET | `/credentials/{name}` | Username and password (basic auth, service account, or a connection's credentials) |
| GET | `/secrets/{name}` | Any secret type (generic shape) |
| GET | `/secrets?prefix=billing/` | Names this client may read (no values) |
| GET | `/status` | This environment's status plus the calling client's name, key expiry and grants |

`{name}` is path-like and lowercase, e.g. `billing/oracle-main` (slashes allowed, no encoding needed).

**Example**

```bash
curl --cacert keyport-ca.crt \
     -H "Authorization: Bearer $KEYPORT_API_KEY" \
     https://keyport.corp.local:9446/api/v1/connections/billing/oracle-main
```

```json
{
  "name": "billing/oracle-main",
  "environment": "Prod",
  "type": "OracleConnection",
  "connectionString": "Data Source=ora-prod-01:1521/BILLPDB;User Id=bill_app;Password=…",
  "components": { "host": "ora-prod-01", "port": 1521, "database": null, "serviceName": "BILLPDB", "sid": null, "username": "bill_app", "password": "…" },
  "version": 7
}
```

```json
// GET /credentials/batch/svc-account
{ "name": "batch/svc-account", "environment": "Prod", "type": "ServiceAccount", "username": "svc_batch", "password": "…", "domain": "CORP", "url": null, "version": 2 }
```

**Status codes**

| Code | Meaning |
|---|---|
| 200 | OK |
| 400 | Secret exists but is a different type than the endpoint serves (e.g. a `BasicAuth` secret requested from `/connections`) |
| 401 | Missing, invalid, disabled, expired, IP-restricted, or **wrong-environment** key. The reason is in the audit trail only. |
| 404 | Not found **or not granted**. The two are indistinguishable, so names cannot be probed. Also returned for any non-API path on an environment port. |
| 429 | Rate limit exceeded (per key) |

**Grant patterns**: `billing/oracle-main` (exact), `billing/*` (everything under `billing/`, any depth), `*` (all secrets in the client's environment). Grants are chosen in the UI from the secrets and folders that **exist** in the environment. The server enforces the same rule, so a grant that matches nothing (a typo or invented name) is refused. Grants a client already has stay valid if their secret is later deleted.

**Admin API** (port 8443, signed-in session, returns 401/403 rather than redirects):
- `GET /admin/api/status`
- `GET /admin/api/health`
- `GET /admin/api/audit`, `/audit/verify` and `/audit/export.csv` (Admin or Auditor)
- `GET /admin/api/activity` and `/activity/export.csv` (Admin or Auditor)

Filters are query parameters: `actor, action, environment, target, result, source, path, minStatus, from, to, skip, take`.

---

## 8. User interface

The UI is desktop-first and responsive: the sidebar becomes a slide-out drawer and tables become stacked cards on phones. It supports light and dark themes (following the OS, with a manual toggle) and is accessible by keyboard. It is written in plain language for non-technical users who set up secrets for others. Screenshots are in the [Tour](#tour) at the top of this README.

**Pages**

| Page | Purpose |
|---|---|
| Dashboard | A **Getting started** checklist (add a secret, give an application access, hand over the key) until the first secret and application exist; health, counts, 24 h traffic, certificate expiry, environment cards, passwords due for a change, recent audit events |
| Secrets | Environment tabs (color-coded, protected ones locked), search, filter by kind |
| Secret editor | Guided, numbered steps in plain language: kind of secret (with descriptions), optional folder plus a free-text name converted to a safe name automatically (with a "saved as" preview and duplicate check), field help with examples, rarely-needed driver settings under *Advanced settings*, a live "Still needed: …" checklist with Save disabled until complete, password generator, test connection, masked preview of what the application receives. Saved secrets show a **"Next step: give an application access"** prompt, the list of applications that can read the secret, audited *Show* (30 s auto-hide) and copy, version history with restore, *Copy to…* another environment, password-change reminder, delete. |
| Compare environments | Matrix of secret names by Dev/Test/Upgrade/Prod with version numbers, to find gaps before a release (no values) |
| Applications (API clients) | Each row shows the key prefix, expiry (**never** by default) and **key age** ("4 months old · issued 18 Jun 2026"; keys over a year old are highlighted with "consider issuing a new key"). Add an application and choose **which secrets it can read from a picker of what exists** (everything, a folder, or individual secrets, shown as a tree with counts and "already covered" hints). This can be started straight from a secret with that secret pre-selected. After creation a **hand-over** panel shows the key once, plus copy-ready setup instructions for the developer (address, the exact requests to make, CA download) that do not contain the key. Edit access, issue a new key, turn off or on, delete. Network restriction is under *Advanced*. |
| Help & guide | Step-by-step "setting up a secret for someone", common tasks (password changed, copy to Prod, app stopped working, key lost), a glossary in plain words, and good habits |
| Status | Listeners, traffic, latency percentiles, jobs, retention, TLS |
| Health | Live health checks with details (auto refresh) |
| Activity log | API and UI request logs with filters and CSV export |
| Audit trail | Security events, chain verification, CSV export |
| Users & access | Create users (temporary password), global roles, Viewer/Editor per environment, reset password, reset MFA, unlock, disable, delete |
| Certificates | CA and server certificate details, fingerprints, CA download, install instructions, force renewal |
| Reverse proxy | Admin-only. Create, edit, enable/disable and delete proxy routes (path prefix, upstreams, load balancing, ports, access level, strip prefix, CSP opt-out, health probe); test upstream reachability; live destination health and 24 h request counts; read-only list of routes from configuration |
| My account | Profile, password, authenticator, recovery codes, passkeys |

---

## 9. Configuration reference

Configuration comes from `appsettings.json` and can be overridden by environment variables using `__` for nesting (e.g. `Keyport__Logs__ApiLogRetentionDays=30`) or by a mounted `appsettings.Production.json`.

| Key | Default | Description |
|---|---|---|
| `Keyport:DataPath` | `/data` | Volume for the database, CA and key ring |
| `Keyport:MasterKeyFile` | `/run/secrets/keyport_master_key` | KEK file. `KEYPORT_MASTER_KEY_FILE` overrides it. |
| `Keyport:BootstrapAdminUser` | `admin` | First administrator account name |
| `Keyport:Edge:HttpPort` | `8080` | Bootstrap HTTP port (`0` disables it) |
| `Keyport:Edge:AdminPort` | `8443` | Admin UI / admin API port |
| `Keyport:Edge:BindAddress` | `0.0.0.0` | Default bind address (`*`/`::` for IPv6 any) |
| `Keyport:Edge:HostNames[]` | `localhost, keyport` | DNS names placed in the TLS certificate. **Set these to the names clients use.** |
| `Keyport:Edge:IpAddresses[]` | `127.0.0.1` | IP SANs |
| `Keyport:Edge:ApiRequestsPerMinute` | `300` | Rate limit per API key |
| `Keyport:Ca:CommonName` | `Keyport Root CA` | Root CA subject |
| `Keyport:Ca:RootLifetimeDays` | `3650` | Root lifetime |
| `Keyport:Ca:LeafLifetimeDays` | `90` | Server certificate lifetime (renewed at 2/3) |
| `Keyport:Ca:ImportPfxPath` | – | Use an enterprise CA instead of a generated root |
| `Keyport:Ca:ImportPfxPasswordFile` | – | Password file for the PFX |
| `Keyport:Logs:ApiLogRetentionDays` | `90` | API activity retention (0 = forever) |
| `Keyport:Logs:UiLogRetentionDays` | `90` | UI activity retention (0 = forever) |
| `Keyport:Logs:AuditRetentionDays` | `0` | Audit retention (0 = forever) |
| `Keyport:Logs:PurgeIntervalHours` | `24` | Retention job frequency |
| `Keyport:Environments[i]:Name` | Dev/Test/Upgrade/Prod | Display name (also the key used to match DB rows) |
| `Keyport:Environments[i]:Port` | 9443–9446 | Listener port (must be unique) |
| `Keyport:Environments[i]:Color` | green/blue/amber/red | UI accent |
| `Keyport:Environments[i]:Protected` | Upgrade, Prod = `true` | Require reasons and show a warning banner |
| `Keyport:Environments[i]:BindAddress` | – | Bind this environment to a specific interface |
| `Keyport:Proxy:AllowedUpstreams[]` | empty | Optional allow-list for UI-managed proxy upstreams (§9.1) |
| `ReverseProxy:Routes / Clusters` | empty | Optional proxy routes defined in configuration (§9.1) |

The order of `Environments` is the **promotion order** (Dev → Test → Upgrade → Prod).

**Adding an environment** (e.g. `UAT` on 9447): add it to `Environments` in the desired position, publish the port in `compose.yaml`, and restart. Removing an environment from configuration deactivates it: its port is closed and its data is kept but not served.

### 9.1 Reverse proxy

Keyport can publish internal services through its own TLS edge, using YARP (Microsoft's reverse proxy). Proxied requests get the same certificate, security headers, port gate and activity logging as everything else.

**Managing routes in the UI (Administration → Reverse proxy, Admin only)**

| Field | Meaning |
|---|---|
| Name | Unique slug (`grafana`) |
| Path prefix | `/grafana`: requests to `/grafana` and everything below it are forwarded. Top-level paths used by Keyport (`/api`, `/admin`, `/Account`, `/secrets`, `/health`, `/_blazor`, …) are refused. |
| Upstream URL(s) | One per line. Several upstreams are load-balanced (PowerOfTwoChoices, RoundRobin, LeastRequests, Random, FirstAlphabetical). |
| Serve on ports | Admin port and/or environment ports. The route returns **404 on every port not selected**. |
| Who can use it | Signed-in users (MFA) · Admins & Auditors · Admins only · Anyone who can reach the port |
| Strip prefix | The upstream sees `/` rather than `/grafana/` |
| Relax CSP | Omit the strict Content-Security-Policy for this route only (many proxied web apps need inline scripts); all other security headers stay |
| Health check path | Optional active probe every 30 s; the destination's health is shown on the page |
| Reason | Required. Every create, update, enable/disable, delete and upstream test goes to the audit trail (`proxy.*`). |

**How it works**
- **Persistence:** routes are stored in the `ProxyRoutes` table of the SQLite database on the `/data` volume.
- **Live updates:** a custom YARP config provider (`DbProxyConfigProvider`) loads them **at every startup** ("Loaded N reverse-proxy route(s) from the database" in the log) and swaps the live configuration **immediately when you save**, with no restart. YARP validates each route before it is saved, so an invalid configuration never goes live.
- **Verified persistence:**
  - The integration test `RoutesPersistAcrossRestart` restarts the server on the same data directory and checks that routes, ports, the CSP setting and disabled state are all restored.
  - It was also checked on the container: a route created in the UI kept serving after `podman restart` and after deleting and re-creating the container on the same volume.

**Upstream allow-list (optional, configuration only)**:

```json
"Keyport": { "Proxy": { "AllowedUpstreams": [ "*.corp.local", "grafana.internal", "10.20.0.0/16" ] } }
```

Entries can be an exact host, a `*.domain` wildcard, or a CIDR (matched against IP-literal upstreams). If the list is empty, any upstream is allowed except link-local and cloud-metadata addresses (169.254.0.0/16, fe80::/10, `metadata.google.internal`), which are always refused. The list can't be changed from the UI, so a compromised admin session cannot widen it.

**Routes from configuration (infrastructure as code)** still work and appear read-only in the UI. Each must name its ports in `Metadata.Ports`:

```json
"ReverseProxy": {
  "Routes": { "docs": { "ClusterId": "docs", "Match": { "Path": "/docs/{**rest}" }, "AuthorizationPolicy": "default", "Metadata": { "Ports": "8443" } } },
  "Clusters": { "docs": { "Destinations": { "d1": { "Address": "http://docs-internal:8080/" } } } }
}
```

**Putting Keyport behind your own proxy** (F5, nginx, an application gateway) is a different setup. Use **TCP/TLS passthrough per port**: the environment is decided by the port the connection arrives on, and `X-Forwarded-*` headers are deliberately ignored.

---

## 10. Deployment and operations

### 10.1 Quick start (Podman; Docker is identical with `docker`)

```bash
# 1. Master key: keep a secure, separate backup of this file
mkdir -p secrets && openssl rand -base64 32 > secrets/keyport_master_key && chmod 644 secrets/keyport_master_key && chmod 700 secrets

# 2. Set the DNS names clients will use in compose.yaml (Keyport__Edge__HostNames__N)

# 3. Build and start
podman build --format docker -t localhost/keyport:latest .   # --format docker keeps the HEALTHCHECK
podman compose up -d

# 4. First sign-in: get the one-time admin password
podman logs keyport 2>&1 | grep -A3 "Bootstrap administrator"

# 5. Trust the CA (verify the fingerprint against the log or Certificates page first)
curl -s http://localhost:8080/ca.crt -o keyport-ca.crt
openssl x509 -in keyport-ca.crt -noout -fingerprint -sha256

# 6. Open https://<host>:8443: sign in, change the password, enrol MFA
```

`secrets/keyport_master_key` must be readable by UID 1654 inside the container; mode `644` inside a `700` directory is the simplest way to achieve that with file-based compose secrets. On Kubernetes, use a Secret mounted at `/run/secrets/keyport_master_key` with `defaultMode: 0400` and `fsGroup: 1654`.

### 10.2 First-run checklist

1. Sign in as `admin`, change the password, enrol MFA, and **store the recovery codes**.
2. Create named administrator accounts and disable or delete the shared `admin` account (keep at least one Admin).
3. Check that `HostNames`/`IpAddresses` match the names clients use. The Certificates page shows the SANs.
4. Distribute the CA certificate to clients' trust stores, or import your enterprise CA (§4.3).
5. Restrict firewall access: :8443 from admin networks, each :94xx from its environment's networks, :8080 as needed for bootstrap.
6. Grant Viewer/Editor per environment, and Auditor to your security team.
7. Configure log retention to meet your policy, and schedule an export of the audit trail to your SIEM.

### 10.3 Try it with demo data

Start an **empty** instance with `--seed-demo` to load data for the fictional company "Nimbus Orbital" and see the product working straight away:

```bash
podman run -d --name sm-demo --init -p 8443:8443 -p 8080:8080 -p 9443-9446:9443-9446 \
  -v sm-demo-data:/data -v ./secrets/keyport_master_key:/run/secrets/keyport_master_key:ro \
  localhost/keyport:latest --seed-demo
podman logs sm-demo 2>&1 | grep -A6 "DEMO data loaded"     # demo users and their shared password
```

It loads:
- **6 users** with different roles (Ava Sterling, Admin; Priya Raman, Auditor; Editors and Viewers per environment)
- **45 secrets** across Dev, Test, Upgrade and Prod, all of them Oracle and SQL Server databases, website/API logins, service accounts and tokens, including deliberate gaps between environments, several versions and overdue password reminders
- **28 applications**, including keys well over a year old, one network-restricted, one expiring and one turned off
- **4 reverse-proxy routes**
- a realistic audit trail

It then runs the server and makes about 400 live API calls so the dashboard, Status and Activity pages have real numbers.

**Safety:** `--seed-demo` refuses to run if the instance already contains any secret, so it can never mix demo data into a real installation. API keys are only held in memory while the traffic is generated; nothing is written to disk. All names, hosts (`*.nimbus.internal`) and people are fictional.

### 10.4 Backup and restore

- **Back up** the `/data` volume (stop the container, or use `sqlite3 .backup` from a sidecar) **and, separately**, the master key.
- **Restore**: put the volume back and supply the **same** master key. At startup the service checks every stored KeyId against the loaded key and refuses to start on a mismatch.

### 10.5 Upgrades

Build or pull the new image and run `podman compose up -d`. EF Core migrations run automatically at startup, and the data on the volume is kept. Downgrades are not supported once a newer migration has been applied; restore from backup instead.

**Upgrading from SecretManager (the pre-rename name):** no manual changes are needed.
- On first start, `secretmanager.db` is renamed to `keyport.db` (together with its WAL/SHM files).
- `SecretManager:*` / `SecretManager__*` settings are still honoured.
- So is `SM_MASTER_KEY_FILE`, and a container secret mounted as `/run/secrets/sm_master_key`.
- **Existing `sm_…` API keys keep working**; new keys start with `kp_`.
- Users must sign in once more, because the session cookie name changed.

With compose, the project, container and volume names changed (`keyport`, `keyport-data`). To carry the data over:

```bash
podman stop secretmanager && podman rm secretmanager                 # old container (its volume is kept)
podman volume create keyport-data
podman volume export secretmanager_sm-data | podman volume import keyport-data -
# the app runs as UID 1654 and must own its data (any small image with chown works)
podman run --rm --user 0 -v keyport-data:/data --entrypoint chown docker.io/library/busybox -R 1654:1654 /data
cp secrets/sm_master_key secrets/keyport_master_key
podman compose up -d --build
```

The old `secretmanager_sm-data` volume is left untouched as a backup. Delete it with `podman volume rm secretmanager_sm-data` once you're satisfied.

### 10.6 Operational runbook

| Situation | Action |
|---|---|
| Health shows `certificates` Degraded | Renewal is overdue. Check the `certificate-renewal` job on the Status page; force renewal from the Certificates page. |
| `audit-chain` Unhealthy | Treat as a security incident: the audit table was modified outside the application. Export the trail, preserve the volume, and investigate the reported event ID. |
| `master-key` Unhealthy / startup refused | The wrong master key was supplied. Supply the original key, or run `--rotate-kek` from the correct key. |
| App gets 401 | Check the audit trail for `api.authenticate` Denied; the details give the exact reason (wrong environment port, expired, disabled, IP not allowed). |
| App gets 404 | The secret doesn't exist in that environment, or the client lacks a grant. Use **Compare environments** and the client's grants. |
| User locked out | Users & access → Unlock |
| User lost MFA device | Users & access → Reset MFA (they re-enrol at next sign-in) |
| API key leaked | API clients → Rotate (the old key dies instantly). Review the activity log for its prefix. |

### 10.7 Capacity

This is a single instance. SQLite in WAL mode with in-process caching comfortably handles thousands of API reads per minute. Clients should cache values for a few minutes (the C# sample does). See §14 for high availability.

---

## 11. Migrating from the WCF service

See **[docs/client-migration.md](docs/client-migration.md)** for the full guide: an operation mapping table, code for .NET, PowerShell and shell, and a rollout plan. In short:

1. Re-create each connection or credential in the matching environment (use **Promote** to carry settings forward, entering each environment's password).
2. Create one API client per application per environment, with narrow grants.
3. Replace the WCF proxy call with one HTTPS GET to the environment's port, using the sample client in `samples/csharp/KeyportClient.cs`.
4. Store the API key in the application's existing secret store (environment variable, Kubernetes secret, or a protected app setting), not in source.

---

## 12. Development and testing

```bash
# Prerequisites: .NET 10 SDK
openssl rand -base64 32 > .localdata/master.key       # dev key (gitignored)
ASPNETCORE_ENVIRONMENT=Development dotnet run --project src/Keyport.Server
# → https://localhost:8443  (dev data in ./.localdata)

dotnet test                                           # 109 tests, about 20 s

dotnet ef migrations add <Name> -p src/Keyport.Server -o Data/Migrations   # after model changes
```

**Automated tests** (`tests/Keyport.Tests`)

| Area | Examples |
|---|---|
| Cryptography | round trip; fresh DEK and nonce per encryption; tampered ciphertext fails; **ciphertext moved to another environment fails**; wrong KEK fails; re-wrap; key file formats |
| API keys / passwords / names | format and verification, malformed keys, generated password strength and connection-string safety, name validation and path-traversal rejection, grant matching |
| Connection strings | SQL Server and Oracle escaping of hostile passwords, Integrated Security, EZConnect vs TNS/SID, extra options, masked preview never leaks |
| Audit chain | intact chain, edited row detected, deleted row detected, field-boundary shift detected |
| CA | chain to root, SANs, server-auth EKU, leaf never outlives issuer, two-thirds renewal threshold, PEM/PKCS#8 round trip |
| **Reverse proxy (real upstream)** | served only on selected ports; prefix stripping; sign-in required for protected routes; live update, disable/enable and delete; CSP opt-out; reserved paths, link-local/metadata, allow-list, scheme and credential validation; Admin-only with reason; upstream test; **routes persist across a server restart** |
| **Integration (real Kestrel + TLS + all listeners)** | read on own port; **4×4 environment/port matrix**; ungranted equals missing; list shows granted names only; disabled, expired and CIDR keys; key rotation; UI/admin routes 404 on env ports; `/api/v1` 404 on the admin port; HTTP bootstrap behavior; health on all ports; client status; **activity log captures 200/404/401**; rate limit 429; protected-environment reasons; promotion never copies the password; versions and rollback; environment-scoped users; validation; ciphertext row binding; audit tamper detection; retention purge with chain anchor; startup refusal with the wrong or missing master key; duplicate ports; admin API 401; security headers and no inline scripts; open-redirect guard |

**End-to-end verification performed on the container** (Podman 5.8, arm64):
- TLS 1.3 verified against the generated CA; port segmentation checks; container health check *healthy*; non-root, read-only root filesystem, no shell.
- Scripted sign-in (password, forced password change, TOTP enrolment with QR code, recovery codes).
- Headless Chrome driven through the real UI: sign-in with TOTP, create a SQL Server secret with a generated password, live masked preview, audited reveal, create an API client and capture the one-time key, then call the API with that key. The key worked on :9443 and got 401 on :9444–9446 and 404 for ungranted names. There were no console or CSP errors. Screenshots are in `docs/images`.

---

## 13. Design decisions

| Decision | Rationale | Alternatives considered |
|---|---|---|
| .NET 10 / ASP.NET Core | Team familiarity from WCF; LTS; first-class SqlClient and Oracle drivers; Kestrel can terminate TLS on many ports with per-handshake certificate selection | Go (smaller image, but a new stack for the team); Node |
| One process, in-process edge | Matches "self-contained, one container". No sidecar to configure or keep in sync. The certificate hot-swap uses Kestrel's `ServerCertificateSelector`. | Caddy/Traefik sidecar (needs a supervisor or two containers, and a second config surface) |
| Environment from the **socket port** | Cannot be spoofed by headers. Firewall rules map naturally to ports. | Host-header or path-based routing (spoofable; harder to firewall) |
| Separate API key per environment | A key leaked from Dev is useless against Prod. Matches how apps are deployed. | One key with multi-environment scopes |
| SQLite on a volume | Zero external dependencies; transactional; trivial backup; plenty fast for this workload | SQL Server or Postgres (straightforward to switch to through EF Core; see §14) |
| Envelope encryption with per-version DEKs | Fast KEK rotation (re-wrap only); per-record cryptographic binding with AAD | Encrypting each field directly with the KEK (rotation re-encrypts everything; no per-row binding) |
| KEK from a file secret | Works identically with Podman, Docker, Kubernetes and Swarm secrets; no cloud dependency | Cloud KMS/HSM (a good future option; see §14) |
| Internal CA | Requirement: no public exposure. Short-lived leaves plus auto-renewal avoid manual certificate work. Can import an enterprise CA. | Let's Encrypt (needs public DNS); manual certificates |
| Blazor Server UI | One language and toolchain; no separate SPA build or CORS; secrets never sit in browser storage | React SPA (extra build, token handling in the browser) |
| Hash-chained audit separate from the activity log | Integrity guarantees where they matter, without making high-volume request logging expensive | One combined log (chain verification becomes slow and noisy) |
| Mandatory MFA, local users | Requirement: self-contained. MFA compensates for the lack of central identity. | OIDC/AD (can be added later through ASP.NET external logins) |

---

## 14. Known limitations and roadmap

| Limitation | Impact | Suggested evolution |
|---|---|---|
| **Single instance** (SQLite; audit-chain writes serialized in-process; in-memory rate limits) | No active-active HA; restart means a short outage | Switch EF provider to SQL Server or Postgres; replace the in-process audit lock with a DB sequence/lock; run 2+ replicas behind a TCP load balancer. Clients should cache values to ride through restarts. |
| Audit chain cannot prove the newest records weren't truncated by a DB-level attacker | Detects edits and deletions *within* the chain, not tail truncation | Scheduled export to SIEM or WORM storage; periodically publish the head hash externally |
| KEK is a file | Anyone with both the volume and the key file can decrypt | Wrap the KEK with a KMS/HSM (Azure Key Vault, AWS KMS, HashiCorp Vault Transit, PKCS#11) |
| TOTP authenticator secrets use Identity's default storage (not KEK-encrypted) | A DB-only compromise could enable TOTP cloning (the password is still required) | Enable Identity personal-data protection with a KEK-backed `ILookupProtector` |
| "Test connection" opens network connections from the server to admin-entered hosts | Editors can probe reachability from the server's network (SSRF-like) | Restrict to an allow-list of DB subnets, or disable through configuration |
| No CRL/OCSP for the internal CA | A compromised server key stays valid until expiry (≤ 90 days) | Shorten `LeafLifetimeDays`; use an enterprise CA with revocation |
| No automation API for secret CRUD (UI only); no bulk import | Large migrations need manual entry | Add admin API tokens and `POST/PUT /admin/api/secrets` plus a CSV/JSON importer |
| Users are local only | No SSO / central deprovisioning | Add OIDC (Entra ID, Okta) as an optional external login, keeping local break-glass admins |
| Activity log is not tamper-evident | Operational data only (security events are in the audit trail) | Ship to SIEM |
| macOS development hosts negotiate TLS 1.2 (platform TLS stack) | Development only; the Linux container negotiates TLS 1.3 | n/a |

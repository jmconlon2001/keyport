namespace Keyport.Server.Configuration;

public sealed class KeyportOptions
{
    public const string Section = "Keyport";

    /// <summary>Settings section used before the product was renamed; still honoured (mapped onto <see cref="Section"/>).</summary>
    public const string LegacySection = "SecretManager";

    /// <summary>
    /// Copies any settings found under the legacy "SecretManager" section to "Keyport" keys. They are added with the
    /// highest precedence, because they can only come from an existing deployment's own configuration.
    /// </summary>
    public static Dictionary<string, string?> LegacyOverrides(IConfiguration configuration) =>
        configuration.GetSection(LegacySection).AsEnumerable(makePathsRelative: true)
            .Where(kv => kv.Value is not null)
            .ToDictionary(kv => $"{Section}:{kv.Key}", kv => kv.Value);

    /// <summary>Directory for the SQLite database, CA material and data-protection keys.</summary>
    public string DataPath { get; set; } = "/data";

    /// <summary>File containing the 32-byte master key (KEK). Overridable with KEYPORT_MASTER_KEY_FILE.</summary>
    public string MasterKeyFile { get; set; } = "/run/secrets/keyport_master_key";

    public EdgeOptions Edge { get; set; } = new();
    public ConnectionTestOptions ConnectionTest { get; set; } = new();
    public AuthOptions Auth { get; set; } = new();
    public CaOptions Ca { get; set; } = new();
    public LogOptions Logs { get; set; } = new();
    public ProxyOptions Proxy { get; set; } = new();

    /// <summary>
    /// Extra secret types defined in configuration (in addition to the built-in ones and any JSON files in
    /// {DataPath}/secret-types). See README "Secret types".
    /// </summary>
    public List<Keyport.Core.Secrets.Types.SecretTypeDefinition> SecretTypes { get; set; } = [];

    /// <summary>Environments in promotion order. Each gets its own listener port.</summary>
    public List<EnvironmentOptions> Environments { get; set; } = [];

    /// <summary>User name of the bootstrap administrator created on first start.</summary>
    public string BootstrapAdminUser { get; set; } = "admin";

    /// <summary>Optional file (e.g. a container secret) holding the first admin's initial password. Otherwise one is generated into {DataPath}/bootstrap-admin.txt.</summary>
    public string? BootstrapAdminPasswordFile { get; set; }
}

public sealed class EdgeOptions
{
    /// <summary>Plain HTTP: redirects to the admin UI and serves /ca.crt and /health for bootstrap. 0 disables.</summary>
    public int HttpPort { get; set; } = 8080;

    /// <summary>HTTPS port for the management UI and admin API.</summary>
    public int AdminPort { get; set; } = 8443;

    /// <summary>Address to bind all listeners to unless an environment overrides it.</summary>
    public string BindAddress { get; set; } = "0.0.0.0";

    /// <summary>DNS names placed in the server certificate's SAN.</summary>
    public List<string> HostNames { get; set; } = ["localhost"];

    /// <summary>IP addresses placed in the server certificate's SAN.</summary>
    public List<string> IpAddresses { get; set; } = ["127.0.0.1"];

    /// <summary>Per-client rate limit on the secrets API.</summary>
    public int ApiRequestsPerMinute { get; set; } = 300;

    /// <summary>Failed API authentications allowed per client IP per minute before that IP gets 429 (no key lookups, no audit writes).</summary>
    public int FailedAuthPerMinute { get; set; } = 30;
}

public sealed class CaOptions
{
    public string CommonName { get; set; } = "Keyport Root CA";
    public int RootLifetimeDays { get; set; } = 3650;
    public int LeafLifetimeDays { get; set; } = 90;

    /// <summary>
    /// Limit a newly generated root to Keyport's own names (Name Constraints), so trusting it doesn't mean trusting it for
    /// every website. Permitted: <c>Edge:HostNames</c> (with subdomains), <c>Edge:IpAddresses</c>, plus the lists below.
    /// Decide these BEFORE the root is created: names added later must fall inside them. Existing roots are unchanged.
    /// </summary>
    public bool NameConstraints { get; set; } = true;
    public List<string> PermittedDnsSuffixes { get; set; } = [];

    /// <summary>
    /// Also constrain IP addresses (to <c>Edge:IpAddresses</c> plus <see cref="PermittedIpRanges"/>). Off by default:
    /// some older TLS stacks (e.g. LibreSSL 2.x, used by macOS's bundled Python 3.9) reject IP name constraints outright.
    /// </summary>
    public bool ConstrainIpAddresses { get; set; }
    public List<string> PermittedIpRanges { get; set; } = [];

    /// <summary>Optional: PFX of an existing enterprise (intermediate) CA to issue from instead of a generated root.</summary>
    public string? ImportPfxPath { get; set; }
    public string? ImportPfxPasswordFile { get; set; }
}

/// <summary>Session limits for people signed in to the UI.</summary>
public sealed class AuthOptions
{
    /// <summary>Sign out after this many minutes without activity (in any open tab).</summary>
    public int IdleTimeoutMinutes { get; set; } = 30;

    /// <summary>Every session ends this many hours after signing in, active or not.</summary>
    public int AbsoluteSessionHours { get; set; } = 8;

    /// <summary>Showing values in a protected environment needs a sign-in or authenticator code from the last N minutes.</summary>
    public int StepUpMinutes { get; set; } = 15;
}

/// <summary>"Test connection" safeguards. The server makes these connections, so they are limited.</summary>
public sealed class ConnectionTestOptions
{
    /// <summary>Turn the Test button off entirely.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Servers that may be tested: CIDR (<c>10.20.0.0/16</c>), IP, exact host or <c>*.corp.local</c>. Empty = any address
    /// except loopback and Keyport's own ports. Link-local / cloud-metadata addresses are always refused.
    /// </summary>
    public List<string> AllowedTargets { get; set; } = [];

    /// <summary>Tests each person may run per minute.</summary>
    public int PerUserPerMinute { get; set; } = 10;
}

public sealed class ProxyOptions
{
    /// <summary>
    /// Optional allow-list for upstreams of UI-managed proxy routes. Entries: exact host name
    /// (<c>grafana.corp.local</c>), wildcard (<c>*.corp.local</c>), or CIDR (<c>10.20.0.0/16</c>, matched against
    /// IP-literal hosts). Empty = any upstream (link-local / cloud-metadata addresses are always refused).
    /// Deliberately configuration-only: the UI cannot widen it.
    /// </summary>
    public List<string> AllowedUpstreams { get; set; } = [];

    /// <summary>
    /// Allow proxy routes on the admin port. Off by default and not recommended: anything an upstream serves there runs
    /// as the admin UI's own origin (its scripts could drive the UI with a signed-in admin's session).
    /// </summary>
    public bool AllowAdminPort { get; set; }
}

public sealed class LogOptions
{
    /// <summary>Days to keep API request log entries. 0 = keep forever.</summary>
    public int ApiLogRetentionDays { get; set; } = 90;

    /// <summary>Days to keep UI activity entries (page views, actions). 0 = keep forever.</summary>
    public int UiLogRetentionDays { get; set; } = 90;

    /// <summary>Days to keep audit events. 0 = keep forever. Purging keeps the hash chain verifiable via a stored anchor.</summary>
    public int AuditRetentionDays { get; set; } = 0;

    public int PurgeIntervalHours { get; set; } = 24;
}

public sealed class EnvironmentOptions
{
    public string Name { get; set; } = "";
    public int Port { get; set; }

    /// <summary>CSS colour used in the UI.</summary>
    public string Color { get; set; } = "#6c757d";

    /// <summary>Protected environments require a reason for every reveal/change and show a warning banner.</summary>
    public bool Protected { get; set; }

    /// <summary>Optional address override, e.g. bind Prod only to a dedicated NIC.</summary>
    public string? BindAddress { get; set; }
}

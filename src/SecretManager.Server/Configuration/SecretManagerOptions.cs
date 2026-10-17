namespace SecretManager.Server.Configuration;

public sealed class SecretManagerOptions
{
    public const string Section = "SecretManager";

    /// <summary>Directory for the SQLite database, CA material and data-protection keys.</summary>
    public string DataPath { get; set; } = "/data";

    /// <summary>File containing the 32-byte master key (KEK). Overridable with SM_MASTER_KEY_FILE.</summary>
    public string MasterKeyFile { get; set; } = "/run/secrets/sm_master_key";

    public EdgeOptions Edge { get; set; } = new();
    public CaOptions Ca { get; set; } = new();
    public LogOptions Logs { get; set; } = new();

    /// <summary>Environments in promotion order. Each gets its own listener port.</summary>
    public List<EnvironmentOptions> Environments { get; set; } = [];

    /// <summary>User name of the bootstrap administrator created on first start.</summary>
    public string BootstrapAdminUser { get; set; } = "admin";
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
}

public sealed class CaOptions
{
    public string CommonName { get; set; } = "SecretManager Root CA";
    public int RootLifetimeDays { get; set; } = 3650;
    public int LeafLifetimeDays { get; set; } = 90;

    /// <summary>Optional: PFX of an existing enterprise (intermediate) CA to issue from instead of a generated root.</summary>
    public string? ImportPfxPath { get; set; }
    public string? ImportPfxPasswordFile { get; set; }
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

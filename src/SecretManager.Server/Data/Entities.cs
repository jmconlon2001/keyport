using SecretManager.Core.Audit;
using SecretManager.Core.Crypto;
using SecretManager.Core.Secrets;

namespace SecretManager.Server.Data;

public class EnvironmentDef
{
    public int Id { get; set; }
    public required string Name { get; set; }
    public int Port { get; set; }
    public string Color { get; set; } = "#6c757d";
    public bool Protected { get; set; }
    public int SortOrder { get; set; }

    /// <summary>False when the environment was removed from configuration; its data is kept but not served.</summary>
    public bool Active { get; set; } = true;
}

public class Secret
{
    public int Id { get; set; }
    public int EnvironmentId { get; set; }
    public EnvironmentDef Environment { get; set; } = null!;
    public required string Name { get; set; }
    public SecretType Type { get; set; }
    public string MetadataJson { get; set; } = "{}";
    public string? Tags { get; set; }
    public int CurrentVersion { get; set; }
    public DateTime? RotateAfterUtc { get; set; }
    public required string CreatedBy { get; set; }
    public DateTime CreatedUtc { get; set; }
    public required string UpdatedBy { get; set; }
    public DateTime UpdatedUtc { get; set; }
    public List<SecretVersion> Versions { get; set; } = [];

    public SecretMetadata Metadata => SecretMetadata.FromJson(MetadataJson);
}

public class SecretVersion
{
    public int Id { get; set; }
    public int SecretId { get; set; }
    public Secret Secret { get; set; } = null!;
    public int Version { get; set; }
    public required byte[] WrappedDek { get; set; }
    public required byte[] Ciphertext { get; set; }
    public required string KeyId { get; set; }
    public required string CreatedBy { get; set; }
    public DateTime CreatedUtc { get; set; }
    public string? Comment { get; set; }

    /// <summary>AAD binds the ciphertext to this exact secret, environment and version.</summary>
    public static string Aad(int secretId, int environmentId, int version) => $"secret|{secretId}|{environmentId}|{version}";

    public EncryptedBlob ToBlob() => new(WrappedDek, Ciphertext, KeyId);
}

public class ApiClient
{
    public int Id { get; set; }
    public int EnvironmentId { get; set; }
    public EnvironmentDef Environment { get; set; } = null!;
    public required string Name { get; set; }
    public string? Description { get; set; }
    public required string KeyPrefix { get; set; }
    public required string KeyHash { get; set; }

    /// <summary>Comma-separated CIDRs; empty means any address.</summary>
    public string? AllowedCidrs { get; set; }
    public DateTime? ExpiresUtc { get; set; }
    public DateTime? LastUsedUtc { get; set; }
    public bool Disabled { get; set; }
    public required string CreatedBy { get; set; }
    public DateTime CreatedUtc { get; set; }

    /// <summary>When the current key was issued (creation or last rotation); the key's age is measured from here.</summary>
    public DateTime KeyCreatedUtc { get; set; }
    public List<ApiClientGrant> Grants { get; set; } = [];
}

public class ApiClientGrant
{
    public int Id { get; set; }
    public int ApiClientId { get; set; }
    public ApiClient ApiClient { get; set; } = null!;

    /// <summary>Exact secret name, <c>prefix/*</c>, or <c>*</c>.</summary>
    public required string Pattern { get; set; }
}

public enum EnvironmentRole
{
    Viewer = 1,
    Editor = 2,
}

public class UserEnvironmentRole
{
    public int Id { get; set; }
    public required string UserId { get; set; }
    public int EnvironmentId { get; set; }
    public EnvironmentDef Environment { get; set; } = null!;
    public EnvironmentRole Role { get; set; }
}

public class AuditEvent : IAuditRecord
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; }
    public required string Actor { get; set; }
    public required string Action { get; set; }
    public string? Environment { get; set; }
    public string? Target { get; set; }
    public required string Result { get; set; }
    public string? ClientIp { get; set; }
    public string? Details { get; set; }
    public required string PrevHash { get; set; }
    public required string Hash { get; set; }
}

public static class LogSource
{
    public const string Api = "Api";
    public const string Ui = "Ui";
}

/// <summary>
/// Every API request and UI action (page views included). High volume and not hash-chained; retention is
/// configured per source. Security-relevant events are additionally written to <see cref="AuditEvent"/>.
/// </summary>
public class ActivityLog
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; }
    public required string Source { get; set; }
    public string? Environment { get; set; }
    public string? Actor { get; set; }
    public string? Method { get; set; }
    public required string Path { get; set; }
    public string? Action { get; set; }
    public string? Target { get; set; }
    public int StatusCode { get; set; }
    public double DurationMs { get; set; }
    public string? ClientIp { get; set; }
    public string? UserAgent { get; set; }
    public string? Error { get; set; }
}

public enum ProxyAccess
{
    /// <summary>Anyone who can reach the port.</summary>
    Anonymous = 0,

    /// <summary>Any signed-in SecretManager user (MFA enforced).</summary>
    SignedIn = 1,

    /// <summary>Admins and Auditors.</summary>
    Auditors = 2,

    /// <summary>Admins only.</summary>
    Admins = 3,
}

/// <summary>A reverse-proxy route managed from the UI (in addition to routes from configuration).</summary>
public class ProxyRoute
{
    public int Id { get; set; }

    /// <summary>Unique slug; used for YARP route/cluster ids ("ui-{Name}").</summary>
    public required string Name { get; set; }
    public string? Description { get; set; }

    /// <summary>Path prefix, e.g. <c>/grafana</c>. Requests to the prefix and everything below it are forwarded.</summary>
    public required string PathPrefix { get; set; }

    /// <summary>Upstream base URLs, one per line.</summary>
    public required string Destinations { get; set; }

    /// <summary>Comma-separated listener ports the route may be served on.</summary>
    public required string Ports { get; set; }

    public ProxyAccess Access { get; set; } = ProxyAccess.SignedIn;
    public bool StripPrefix { get; set; } = true;

    /// <summary>Skip SecretManager's strict Content-Security-Policy for this route (needed by many proxied web apps).</summary>
    public bool RelaxCsp { get; set; }

    public string LoadBalancing { get; set; } = "PowerOfTwoChoices";

    /// <summary>Optional upstream path probed every 30 s (active health check), e.g. <c>/healthz</c>.</summary>
    public string? HealthCheckPath { get; set; }

    public bool Enabled { get; set; } = true;
    public required string CreatedBy { get; set; }
    public DateTime CreatedUtc { get; set; }
    public required string UpdatedBy { get; set; }
    public DateTime UpdatedUtc { get; set; }

    public IEnumerable<string> DestinationList =>
        Destinations.Split(['\n', '\r', ','], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public IEnumerable<int> PortList =>
        Ports.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(int.Parse);
}

/// <summary>Small key/value store for app-level state (e.g. CA material, wrapped with the KEK).</summary>
public class AppSetting
{
    public required string Key { get; set; }
    public required string Value { get; set; }
}

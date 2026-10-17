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

/// <summary>Small key/value store for app-level state (e.g. CA material, wrapped with the KEK).</summary>
public class AppSetting
{
    public required string Key { get; set; }
    public required string Value { get; set; }
}

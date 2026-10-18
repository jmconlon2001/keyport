using System.Text.Json;
using System.Text.Json.Serialization;

namespace Keyport.Core.Secrets;

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum SecretType
{
    OracleConnection,
    SqlServerConnection,
    BasicAuth,
    ServiceAccount,
    Generic,
}

public static class SecretTypes
{
    public static bool IsConnection(this SecretType t) => t is SecretType.OracleConnection or SecretType.SqlServerConnection;
    public static bool IsCredential(this SecretType t) => t is SecretType.BasicAuth or SecretType.ServiceAccount;

    /// <summary>Plain-language title for people who don't know the technical term.</summary>
    public static string FriendlyTitle(this SecretType t) => t switch
    {
        SecretType.OracleConnection => "Oracle database",
        SecretType.SqlServerConnection => "SQL Server database",
        SecretType.BasicAuth => "Website or API login",
        SecretType.ServiceAccount => "Service account",
        _ => "Other secret",
    };

    public static string FriendlyDescription(this SecretType t) => t switch
    {
        SecretType.OracleConnection => "Server, service name and login for an Oracle database.",
        SecretType.SqlServerConnection => "Server, database and login for a Microsoft SQL Server database.",
        SecretType.BasicAuth => "A username and password used to sign in to a website or web service.",
        SecretType.ServiceAccount => "A Windows / Active Directory account that a program or scheduled job runs as.",
        _ => "Any other value, such as an API token or licence key.",
    };

    public static string DisplayName(this SecretType t) => t switch
    {
        SecretType.OracleConnection => "Oracle connection",
        SecretType.SqlServerConnection => "SQL Server connection",
        SecretType.BasicAuth => "Basic auth",
        SecretType.ServiceAccount => "Service account",
        _ => "Generic secret",
    };
}

/// <summary>Non-sensitive descriptive fields. Stored in clear text so they can be searched, compared and promoted.</summary>
public sealed class SecretMetadata
{
    public string? Description { get; set; }

    // Database connections
    public string? Host { get; set; }
    public int? Port { get; set; }

    /// <summary>SQL Server: initial catalog.</summary>
    public string? Database { get; set; }

    /// <summary>Oracle: service name (preferred) or SID.</summary>
    public string? ServiceName { get; set; }
    public string? Sid { get; set; }

    /// <summary>Oracle: emit a full TNS DESCRIPTION instead of EZConnect host:port/service.</summary>
    public bool UseTnsDescriptor { get; set; }

    /// <summary>SQL Server: Mandatory | Optional | Strict.</summary>
    public string? Encrypt { get; set; } = "Mandatory";
    public bool TrustServerCertificate { get; set; }
    public bool IntegratedSecurity { get; set; }
    public string? ApplicationName { get; set; }

    /// <summary>Additional driver options as <c>Key=Value;Key2=Value2</c>.</summary>
    public string? ExtraOptions { get; set; }

    // Credentials
    public string? Domain { get; set; }

    /// <summary>Basic auth: the endpoint these credentials are for (informational).</summary>
    public string? Url { get; set; }

    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public string ToJson() => JsonSerializer.Serialize(this, Json);
    public static SecretMetadata FromJson(string? json) =>
        string.IsNullOrWhiteSpace(json) ? new() : JsonSerializer.Deserialize<SecretMetadata>(json, Json) ?? new();

    public SecretMetadata Clone() => FromJson(ToJson());
}

/// <summary>Sensitive fields. Serialized to JSON and envelope-encrypted as one blob per version.</summary>
public sealed class SecretPayload
{
    public string? Username { get; set; }
    public string? Password { get; set; }

    /// <summary>Generic secrets: the value.</summary>
    public string? Value { get; set; }

    /// <summary>Optional verbatim connection string that replaces the generated one.</summary>
    public string? ConnectionStringOverride { get; set; }

    public string ToJson() => JsonSerializer.Serialize(this, SecretMetadata.Json);
    public static SecretPayload FromJson(string json) => JsonSerializer.Deserialize<SecretPayload>(json, SecretMetadata.Json) ?? new();
}

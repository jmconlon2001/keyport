using System.Text.Json;
using System.Text.Json.Serialization;
using Keyport.Core.Secrets.Types;

namespace Keyport.Core.Secrets;

/// <summary>
/// The kind of a secret, identified by its type key (e.g. "SqlServerConnection", "PostgresConnection").
/// Behaviour (fields, outputs, titles) comes from the <see cref="SecretTypeDefinition"/> in
/// <see cref="SecretTypeRegistry.Current"/>, so new types need no code here. The built-in keys match the values
/// stored before types became pluggable, so existing data loads unchanged.
/// </summary>
[JsonConverter(typeof(SecretTypeJsonConverter))]
public readonly record struct SecretType(string Key)
{
    public static readonly SecretType OracleConnection = new("OracleConnection");
    public static readonly SecretType SqlServerConnection = new("SqlServerConnection");
    public static readonly SecretType BasicAuth = new("BasicAuth");
    public static readonly SecretType ServiceAccount = new("ServiceAccount");
    public static readonly SecretType Generic = new("Generic");

    public SecretTypeDefinition Definition => SecretTypeRegistry.Current.Get(Key);

    /// <summary>Served by <c>/api/v1/connections</c>: the type produces a connection string.</summary>
    public bool IsConnection() => Definition.HasOutput(OutputKeys.ConnectionString);

    /// <summary>A login (username + password) that is not a connection, e.g. basic auth or a service account.</summary>
    public bool IsCredential() => !IsConnection() && Definition.HasUsernameAndPassword;

    /// <summary>Plain-language title for people who don't know the technical term.</summary>
    public string FriendlyTitle() => Definition.Title;
    public string FriendlyDescription() => Definition.Description;
    public string DisplayName() => Definition.Title;

    public override string ToString() => Key ?? "";
}

public sealed class SecretTypeJsonConverter : JsonConverter<SecretType>
{
    public override SecretType Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        new(reader.GetString() ?? "");

    public override void Write(Utf8JsonWriter writer, SecretType value, JsonSerializerOptions options) =>
        writer.WriteStringValue(value.Key);
}

/// <summary>
/// A bag of named field values (string per field key, case-insensitive). Serialized as a flat JSON object.
/// Reads values written by earlier versions, where some fields were JSON numbers or booleans.
/// </summary>
public class SecretFields
{
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly Dictionary<string, string?> _values = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Gets or sets a field. Setting null or "" removes it.</summary>
    public string? this[string key]
    {
        get => _values.TryGetValue(key, out var v) ? v : null;
        set
        {
            if (string.IsNullOrEmpty(value)) _values.Remove(key);
            else _values[key] = value;
        }
    }

    public IReadOnlyDictionary<string, string?> Values => _values;
    public IEnumerable<string> Keys => _values.Keys;
    public bool Has(string key) => !string.IsNullOrEmpty(this[key]);

    protected int? GetInt(string key) => int.TryParse(this[key], out var i) ? i : null;
    protected void SetInt(string key, int? value) => this[key] = value?.ToString(System.Globalization.CultureInfo.InvariantCulture);
    protected bool GetBool(string key) => IsTrue(this[key]);
    protected void SetBool(string key, bool value) => this[key] = value ? "true" : null;

    public static bool IsTrue(string? value) => string.Equals(value, "true", StringComparison.OrdinalIgnoreCase);

    public string ToJson() => JsonSerializer.Serialize(_values.Where(kv => kv.Value is not null).ToDictionary(kv => kv.Key, kv => kv.Value), Json);

    protected void LoadJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return;
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.ValueKind != JsonValueKind.Object) return;
        foreach (var p in doc.RootElement.EnumerateObject())
        {
            this[p.Name] = p.Value.ValueKind switch
            {
                JsonValueKind.String => p.Value.GetString(),
                JsonValueKind.Number => p.Value.GetRawText(),
                JsonValueKind.True => "true",
                JsonValueKind.False => "false",
                _ => null,
            };
        }
    }

    protected void CopyFrom(SecretFields other)
    {
        foreach (var (k, v) in other._values) _values[k] = v;
    }

    /// <summary>All values of two bags (the second wins on conflicts), used to render outputs.</summary>
    public static Dictionary<string, string?> Merge(SecretFields a, SecretFields b)
    {
        var merged = new Dictionary<string, string?>(a._values, StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in b._values) merged[k] = v;
        return merged;
    }
}

/// <summary>
/// Non-sensitive fields, stored in clear text so they can be searched, compared and copied between environments.
/// The typed properties are conveniences over the generic field bag (keys match the stored JSON).
/// </summary>
public sealed class SecretMetadata : SecretFields
{
    public string? Description { get => this["description"]; set => this["description"] = value; }
    public string? Host { get => this["host"]; set => this["host"] = value; }
    public int? Port { get => GetInt("port"); set => SetInt("port", value); }
    public string? Database { get => this["database"]; set => this["database"] = value; }
    public string? ServiceName { get => this["serviceName"]; set => this["serviceName"] = value; }
    public string? Sid { get => this["sid"]; set => this["sid"] = value; }
    public bool UseTnsDescriptor { get => GetBool("useTnsDescriptor"); set => SetBool("useTnsDescriptor", value); }
    public string? Encrypt { get => this["encrypt"]; set => this["encrypt"] = value; }
    public bool TrustServerCertificate { get => GetBool("trustServerCertificate"); set => SetBool("trustServerCertificate", value); }
    public bool IntegratedSecurity { get => GetBool("integratedSecurity"); set => SetBool("integratedSecurity", value); }
    public string? ApplicationName { get => this["applicationName"]; set => this["applicationName"] = value; }
    public string? ExtraOptions { get => this["extraOptions"]; set => this["extraOptions"] = value; }
    public string? Domain { get => this["domain"]; set => this["domain"] = value; }
    public string? Url { get => this["url"]; set => this["url"] = value; }

    public static SecretMetadata FromJson(string? json)
    {
        var m = new SecretMetadata();
        m.LoadJson(json);
        return m;
    }

    public static SecretMetadata From(IEnumerable<KeyValuePair<string, string?>> values)
    {
        var m = new SecretMetadata();
        foreach (var (k, v) in values) m[k] = v;
        return m;
    }

    public SecretMetadata Clone()
    {
        var m = new SecretMetadata();
        m.CopyFrom(this);
        return m;
    }
}

/// <summary>Sensitive fields. Serialized to JSON and envelope-encrypted as one blob per version.</summary>
public sealed class SecretPayload : SecretFields
{
    public string? Username { get => this["username"]; set => this["username"] = value; }
    public string? Password { get => this["password"]; set => this["password"] = value; }

    /// <summary>Generic secrets: the value.</summary>
    public string? Value { get => this["value"]; set => this["value"] = value; }

    /// <summary>Optional verbatim connection string that replaces the generated one.</summary>
    public string? ConnectionStringOverride { get => this["connectionStringOverride"]; set => this["connectionStringOverride"] = value; }

    public static SecretPayload FromJson(string json)
    {
        var p = new SecretPayload();
        p.LoadJson(json);
        return p;
    }

    public static SecretPayload From(IEnumerable<KeyValuePair<string, string?>> values)
    {
        var p = new SecretPayload();
        foreach (var (k, v) in values) p[k] = v;
        return p;
    }

    public SecretPayload Clone()
    {
        var p = new SecretPayload();
        p.CopyFrom(this);
        return p;
    }
}

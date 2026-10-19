using System.Data.Common;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Keyport.Core.Secrets.Types;
using Microsoft.Data.SqlClient;
using Oracle.ManagedDataAccess.Client;

namespace Keyport.Core.Secrets.Renderers;

/// <summary>Builds one output (e.g. a connection string) from a secret's field values, escaping for the target format.</summary>
public interface ISecretRenderer
{
    string Name { get; }

    string Render(OutputDefinition output, IReadOnlyDictionary<string, string?> values);

    /// <summary>Optional check of the rendered result (e.g. "does the driver parse it"). Returns an error message or null.</summary>
    string? Validate(OutputDefinition output, IReadOnlyDictionary<string, string?> values, string rendered) => null;

    /// <summary>Checks the output's settings when a type is registered. Returns an error message or null.</summary>
    string? ValidateSettings(IReadOnlyDictionary<string, string> settings, IReadOnlySet<string> fieldKeys) => null;
}

internal static class RendererHelpers
{
    public static string? Get(this IReadOnlyDictionary<string, string?> v, string key) =>
        v.TryGetValue(key, out var s) && !string.IsNullOrEmpty(s) ? s : null;

    public static string? CheckFields(IEnumerable<string> referenced, IReadOnlySet<string> fieldKeys)
    {
        var bad = referenced.FirstOrDefault(r => r.Length > 0 && !fieldKeys.Contains(r));
        return bad is null ? null : $"refers to unknown field '{bad}'";
    }

    public static void ApplyExtras(DbConnectionStringBuilder b, string? extras)
    {
        if (string.IsNullOrWhiteSpace(extras)) return;
        var parsed = new DbConnectionStringBuilder { ConnectionString = extras };
        foreach (string key in parsed.Keys)
            b[key] = parsed[key];
    }
}

/// <summary>SQL Server connection string via SqlConnectionStringBuilder.</summary>
public sealed class SqlServerRenderer : ISecretRenderer
{
    public string Name => "sqlserver";

    public string Render(OutputDefinition output, IReadOnlyDictionary<string, string?> values)
    {
        var meta = SecretMetadata.From(values);
        var payload = SecretPayload.From(values);
        var b = new SqlConnectionStringBuilder
        {
            DataSource = meta.Port is > 0 ? $"{meta.Host},{meta.Port}" : meta.Host ?? "",
        };
        if (!string.IsNullOrWhiteSpace(meta.Database)) b.InitialCatalog = meta.Database;

        if (meta.IntegratedSecurity)
        {
            b.IntegratedSecurity = true;
        }
        else
        {
            if (!string.IsNullOrEmpty(payload.Username)) b.UserID = payload.Username;
            if (!string.IsNullOrEmpty(payload.Password)) b.Password = payload.Password;
        }

        if (!string.IsNullOrWhiteSpace(meta.Encrypt)) b.Encrypt = SqlConnectionEncryptOption.Parse(meta.Encrypt);
        if (meta.TrustServerCertificate) b.TrustServerCertificate = true;
        if (!string.IsNullOrWhiteSpace(meta.ApplicationName)) b.ApplicationName = meta.ApplicationName;

        RendererHelpers.ApplyExtras(b, meta.ExtraOptions);
        return b.ConnectionString;
    }

    public string? Validate(OutputDefinition output, IReadOnlyDictionary<string, string?> values, string rendered) =>
        ConnectionStringFactory.TryParse(SecretType.SqlServerConnection, rendered, out var e) ? null : $"not valid for the SQL Server driver: {e}";
}

/// <summary>Oracle connection string (EZConnect or full TNS descriptor) via OracleConnectionStringBuilder.</summary>
public sealed class OracleRenderer : ISecretRenderer
{
    public string Name => "oracle";

    public string Render(OutputDefinition output, IReadOnlyDictionary<string, string?> values)
    {
        var meta = SecretMetadata.From(values);
        var payload = SecretPayload.From(values);
        var b = new OracleConnectionStringBuilder { DataSource = ConnectionStringFactory.OracleDataSource(meta) };
        if (!string.IsNullOrEmpty(payload.Username)) b.UserID = payload.Username;
        if (!string.IsNullOrEmpty(payload.Password)) b.Password = payload.Password;
        RendererHelpers.ApplyExtras(b, meta.ExtraOptions);
        return b.ConnectionString;
    }

    public string? Validate(OutputDefinition output, IReadOnlyDictionary<string, string?> values, string rendered) =>
        ConnectionStringFactory.TryParse(SecretType.OracleConnection, rendered, out var e) ? null : $"not valid for the Oracle driver: {e}";
}

/// <summary>
/// ADO.NET-style "Key=Value;" string (PostgreSQL/Npgsql, MySQL, ODBC…), escaped by DbConnectionStringBuilder.
/// Settings: <c>map</c> = "Host=host;Port=port;Username=username;…" (output key = field key), optional <c>extraField</c>.
/// </summary>
public sealed class KeyValueRenderer : ISecretRenderer
{
    public string Name => "keyvalue";

    private static IEnumerable<(string OutKey, string Field)> Map(IReadOnlyDictionary<string, string> s) =>
        (s.TryGetValue("map", out var m) ? m : "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(p => p.Split('=', 2)).Where(p => p.Length == 2).Select(p => (p[0].Trim(), p[1].Trim()));

    public string Render(OutputDefinition output, IReadOnlyDictionary<string, string?> values)
    {
        var b = new DbConnectionStringBuilder();
        foreach (var (outKey, field) in Map(output.Settings))
            if (values.Get(field) is { } v) b[outKey] = v;
        if (output.Settings.TryGetValue("extraField", out var extra)) RendererHelpers.ApplyExtras(b, values.Get(extra));
        return b.ConnectionString;
    }

    public string? Validate(OutputDefinition output, IReadOnlyDictionary<string, string?> values, string rendered)
    {
        try
        {
            _ = new DbConnectionStringBuilder { ConnectionString = rendered };
            return null;
        }
        catch (ArgumentException e)
        {
            return e.Message;
        }
    }

    public string? ValidateSettings(IReadOnlyDictionary<string, string> settings, IReadOnlySet<string> fieldKeys)
    {
        var map = Map(settings).ToList();
        if (map.Count == 0) return "keyvalue needs a 'map' setting like \"Host=host;Port=port\"";
        return RendererHelpers.CheckFields(map.Select(m => m.Field).Append(settings.TryGetValue("extraField", out var e) ? e : ""), fieldKeys);
    }
}

/// <summary>
/// URL such as mongodb://user:pass@host/db?x=y or rediss://… . User, password and path are percent-encoded.
/// Settings: scheme, tlsScheme + tlsField (switch scheme when a boolean is true), host (field, default "host"),
/// hostIsList ("true": host field holds "h1:p1,h2:p2" as-is), port, path, user, password, query ("q=field&q2=field2").
/// </summary>
public sealed class UriRenderer : ISecretRenderer
{
    public string Name => "uri";

    private static string S(IReadOnlyDictionary<string, string> s, string key, string fallback = "") => s.TryGetValue(key, out var v) ? v : fallback;

    private static IEnumerable<(string Param, string Field)> Query(IReadOnlyDictionary<string, string> s) =>
        S(s, "query").Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=', 2)).Where(p => p.Length == 2).Select(p => (p[0], p[1]));

    public string Render(OutputDefinition output, IReadOnlyDictionary<string, string?> values)
    {
        var s = output.Settings;
        var scheme = S(s, "scheme");
        if (S(s, "tlsField") is { Length: > 0 } tf && SecretFields.IsTrue(values.Get(tf)) && S(s, "tlsScheme") is { Length: > 0 } ts)
            scheme = ts;

        var sb = new StringBuilder(scheme).Append("://");
        var user = values.Get(S(s, "user"));
        var pass = values.Get(S(s, "password"));
        if (user is not null || pass is not null)
        {
            sb.Append(Uri.EscapeDataString(user ?? ""));
            if (pass is not null) sb.Append(':').Append(Uri.EscapeDataString(pass));
            sb.Append('@');
        }

        sb.Append(values.Get(S(s, "host", "host")) ?? "");
        if (!SecretFields.IsTrue(S(s, "hostIsList")) && values.Get(S(s, "port")) is { } port) sb.Append(':').Append(port);

        var path = values.Get(S(s, "path"));
        sb.Append('/');
        if (path is not null) sb.Append(Uri.EscapeDataString(path));

        var q = Query(s).Select(p => (p.Param, Value: values.Get(p.Field))).Where(p => p.Value is not null).ToList();
        if (q.Count > 0) sb.Append('?').Append(string.Join('&', q.Select(p => $"{Uri.EscapeDataString(p.Param)}={Uri.EscapeDataString(p.Value!)}")));
        return sb.ToString();
    }

    public string? Validate(OutputDefinition output, IReadOnlyDictionary<string, string?> values, string rendered) =>
        SecretFields.IsTrue(S(output.Settings, "hostIsList")) || Uri.TryCreate(rendered, UriKind.Absolute, out _) ? null : "the generated address is not valid";

    public string? ValidateSettings(IReadOnlyDictionary<string, string> settings, IReadOnlySet<string> fieldKeys)
    {
        if (S(settings, "scheme").Length == 0) return "uri needs a 'scheme' setting";
        return RendererHelpers.CheckFields(
            new[] { S(settings, "host", "host"), S(settings, "port"), S(settings, "path"), S(settings, "user"), S(settings, "password"), S(settings, "tlsField") }
                .Concat(Query(settings).Select(q => q.Field)), fieldKeys);
    }
}

/// <summary>
/// Text template with <c>{{field}}</c> or <c>{{field|encoder}}</c> placeholders. Encoders: none, url, json, base64,
/// quoted (escapes \ and " for quoted strings such as JAAS configs). Setting: <c>template</c>.
/// </summary>
public sealed partial class TemplateRenderer : ISecretRenderer
{
    public string Name => "template";

    [GeneratedRegex(@"\{\{\s*([A-Za-z0-9_]+)\s*(?:\|\s*([a-z0-9]+)\s*)?\}\}")]
    private static partial Regex Placeholder();

    private static readonly HashSet<string> Encoders = ["none", "url", "json", "base64", "quoted"];

    public string Render(OutputDefinition output, IReadOnlyDictionary<string, string?> values) =>
        Placeholder().Replace(output.Settings.TryGetValue("template", out var t) ? t : "", m =>
        {
            var v = values.Get(m.Groups[1].Value) ?? "";
            return (m.Groups[2].Success ? m.Groups[2].Value : "none") switch
            {
                "url" => Uri.EscapeDataString(v),
                "json" => System.Text.Json.JsonEncodedText.Encode(v).ToString(),
                "base64" => Convert.ToBase64String(Encoding.UTF8.GetBytes(v)),
                "quoted" => v.Replace("\\", "\\\\").Replace("\"", "\\\""),
                _ => v,
            };
        });

    public string? ValidateSettings(IReadOnlyDictionary<string, string> settings, IReadOnlySet<string> fieldKeys)
    {
        if (!settings.TryGetValue("template", out var t) || string.IsNullOrWhiteSpace(t)) return "template needs a 'template' setting";
        foreach (Match m in Placeholder().Matches(t))
        {
            if (!fieldKeys.Contains(m.Groups[1].Value)) return $"template refers to unknown field '{m.Groups[1].Value}'";
            if (m.Groups[2].Success && !Encoders.Contains(m.Groups[2].Value)) return $"unknown encoder '{m.Groups[2].Value}' (use {string.Join(", ", Encoders)})";
        }
        return null;
    }
}

/// <summary>
/// PEM bundle: concatenates PEM fields in order (setting <c>fields</c>, e.g. "certificate,chain,privateKey").
/// With <c>certificateField</c> and <c>keyField</c> it also checks the certificate parses and matches the key.
/// </summary>
public sealed class PemBundleRenderer : ISecretRenderer
{
    public string Name => "pem-bundle";

    private static string[] Fields(IReadOnlyDictionary<string, string> s) =>
        (s.TryGetValue("fields", out var f) ? f : "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public string Render(OutputDefinition output, IReadOnlyDictionary<string, string?> values) =>
        string.Join('\n', Fields(output.Settings).Select(f => values.Get(f)?.Trim()).Where(v => v is not null)) + "\n";

    public string? Validate(OutputDefinition output, IReadOnlyDictionary<string, string?> values, string rendered)
    {
        if (!output.Settings.TryGetValue("certificateField", out var cf) || values.Get(cf) is not { } cert) return null;
        try
        {
            if (output.Settings.TryGetValue("keyField", out var kf) && values.Get(kf) is { } key)
            {
                using var withKey = X509Certificate2.CreateFromPem(cert, key);
                return null;
            }
            using var c = X509Certificate2.CreateFromPem(cert);
            return null;
        }
        catch (CryptographicException e)
        {
            return $"the certificate and private key don't parse or don't match ({e.Message})";
        }
        catch (ArgumentException e)
        {
            return $"the certificate isn't valid PEM ({e.Message})";
        }
    }

    public string? ValidateSettings(IReadOnlyDictionary<string, string> settings, IReadOnlySet<string> fieldKeys)
    {
        var fields = Fields(settings);
        if (fields.Length == 0) return "pem-bundle needs a 'fields' setting";
        return RendererHelpers.CheckFields(fields.Append(settings.TryGetValue("certificateField", out var c) ? c : "").Append(settings.TryGetValue("keyField", out var k) ? k : ""), fieldKeys);
    }
}

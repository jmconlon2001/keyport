using System.Data.Common;
using Microsoft.Data.SqlClient;
using Oracle.ManagedDataAccess.Client;

namespace Keyport.Core.Secrets;

public static class ConnectionStringFactory
{
    public const string Mask = "********";

    /// <summary>Builds a driver-ready connection string. Values are escaped by the driver's own builder.</summary>
    public static string Build(SecretType type, SecretMetadata meta, SecretPayload payload)
    {
        if (!string.IsNullOrWhiteSpace(payload.ConnectionStringOverride))
            return payload.ConnectionStringOverride;

        return type switch
        {
            SecretType.SqlServerConnection => BuildSqlServer(meta, payload),
            SecretType.OracleConnection => BuildOracle(meta, payload),
            _ => throw new ArgumentException($"{type} is not a connection type.", nameof(type)),
        };
    }

    /// <summary>Same as <see cref="Build"/> but with the password replaced by a mask, for UI previews.</summary>
    public static string BuildMasked(SecretType type, SecretMetadata meta, SecretPayload payload)
    {
        if (!string.IsNullOrWhiteSpace(payload.ConnectionStringOverride))
            return MaskPassword(payload.ConnectionStringOverride);

        var masked = new SecretPayload
        {
            Username = payload.Username,
            Password = string.IsNullOrEmpty(payload.Password) ? null : Mask,
        };
        return Build(type, meta, masked);
    }

    public static string BuildSqlServer(SecretMetadata meta, SecretPayload payload)
    {
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

        ApplyExtras(b, meta.ExtraOptions);
        return b.ConnectionString;
    }

    public static string BuildOracle(SecretMetadata meta, SecretPayload payload)
    {
        var b = new OracleConnectionStringBuilder { DataSource = OracleDataSource(meta) };
        if (!string.IsNullOrEmpty(payload.Username)) b.UserID = payload.Username;
        if (!string.IsNullOrEmpty(payload.Password)) b.Password = payload.Password;
        ApplyExtras(b, meta.ExtraOptions);
        return b.ConnectionString;
    }

    public static string OracleDataSource(SecretMetadata meta)
    {
        var host = meta.Host ?? "";
        var port = meta.Port is > 0 ? meta.Port.Value : 1521;

        if (!meta.UseTnsDescriptor)
        {
            // EZConnect: host:port/service_name. SID-only targets need the descriptor form.
            if (!string.IsNullOrWhiteSpace(meta.ServiceName) || string.IsNullOrWhiteSpace(meta.Sid))
                return $"{host}:{port}/{meta.ServiceName}";
        }

        var connectData = !string.IsNullOrWhiteSpace(meta.ServiceName)
            ? $"(SERVICE_NAME={meta.ServiceName})"
            : $"(SID={meta.Sid})";
        return $"(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={port}))(CONNECT_DATA={connectData}))";
    }

    /// <summary>Validates that a connection string parses with the target driver's builder.</summary>
    public static bool TryParse(SecretType type, string connectionString, out string? error)
    {
        try
        {
            DbConnectionStringBuilder b = type == SecretType.OracleConnection
                ? new OracleConnectionStringBuilder(connectionString)
                : new SqlConnectionStringBuilder(connectionString);
            error = null;
            return b.Count > 0;
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or KeyNotFoundException)
        {
            error = ex.Message;
            return false;
        }
    }

    private static void ApplyExtras(DbConnectionStringBuilder b, string? extras)
    {
        if (string.IsNullOrWhiteSpace(extras)) return;
        var parsed = new DbConnectionStringBuilder { ConnectionString = extras };
        foreach (string key in parsed.Keys)
            b[key] = parsed[key];
    }

    private static string MaskPassword(string cs)
    {
        try
        {
            var b = new DbConnectionStringBuilder { ConnectionString = cs };
            foreach (var key in new[] { "Password", "Pwd" })
                if (b.ContainsKey(key)) b[key] = Mask;
            return b.ConnectionString;
        }
        catch (ArgumentException)
        {
            return Mask;
        }
    }
}

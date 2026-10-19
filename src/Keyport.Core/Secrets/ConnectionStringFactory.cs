using System.Data.Common;
using Keyport.Core.Secrets.Types;
using Microsoft.Data.SqlClient;
using Oracle.ManagedDataAccess.Client;

namespace Keyport.Core.Secrets;

/// <summary>
/// Convenience API for connection strings. Rendering is driven by the secret type's definition and renderers
/// (see <see cref="SecretTypeRegistry"/>); this class keeps the original call shape for existing callers.
/// </summary>
public static class ConnectionStringFactory
{
    public const string Mask = SecretTypeRegistry.Mask;

    /// <summary>Builds a driver-ready connection string. Values are escaped by the driver's own builder.</summary>
    public static string Build(SecretType type, SecretMetadata meta, SecretPayload payload)
    {
        var def = type.Definition;
        var output = def.Outputs.FirstOrDefault(o => o.Key == OutputKeys.ConnectionString)
            ?? throw new ArgumentException($"{type} is not a connection type.", nameof(type));
        return SecretTypeRegistry.Current.Render(def, output, SecretFields.Merge(meta, payload));
    }

    /// <summary>Same as <see cref="Build"/> but with the password replaced by a mask, for UI previews.</summary>
    public static string BuildMasked(SecretType type, SecretMetadata meta, SecretPayload payload) =>
        SecretTypeRegistry.Current.RenderMasked(type.Definition, SecretFields.Merge(meta, payload)).GetValueOrDefault(OutputKeys.ConnectionString)
            ?? throw new ArgumentException($"{type} is not a connection type.", nameof(type));

    public static string BuildSqlServer(SecretMetadata meta, SecretPayload payload) => Build(SecretType.SqlServerConnection, meta, payload);
    public static string BuildOracle(SecretMetadata meta, SecretPayload payload) => Build(SecretType.OracleConnection, meta, payload);

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
                : type == SecretType.SqlServerConnection
                    ? new SqlConnectionStringBuilder(connectionString)
                    : new DbConnectionStringBuilder { ConnectionString = connectionString };
            error = null;
            return b.Count > 0;
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or KeyNotFoundException)
        {
            error = ex.Message;
            return false;
        }
    }

    public static string MaskPassword(string cs)
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

using System.Data.Common;
using System.Diagnostics;
using Microsoft.Data.SqlClient;
using Oracle.ManagedDataAccess.Client;
using SecretManager.Core.Secrets;

namespace SecretManager.Server.Services;

public sealed record ConnectionTestResult(bool Success, string Message, double ElapsedMs);

/// <summary>Opens (and immediately closes) a real connection to verify stored connection settings.</summary>
public sealed class ConnectionTester
{
    public async Task<ConnectionTestResult> TestAsync(SecretType type, SecretMetadata meta, SecretPayload payload, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        try
        {
            var cs = ConnectionStringFactory.Build(type, meta, payload);
            await using DbConnection conn = type switch
            {
                SecretType.SqlServerConnection => new SqlConnection(new SqlConnectionStringBuilder(cs) { ConnectTimeout = 8 }.ConnectionString),
                SecretType.OracleConnection => new OracleConnection(new OracleConnectionStringBuilder(cs) { ConnectionTimeout = 8 }.ConnectionString),
                _ => throw new ArgumentException("Only database connections can be tested."),
            };
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            await conn.OpenAsync(timeout.Token);
            var version = conn.ServerVersion;
            return new ConnectionTestResult(true, $"Connected. Server version {version}.", sw.Elapsed.TotalMilliseconds);
        }
        catch (Exception ex)
        {
            // Driver messages can echo the connection string on some errors; keep only the first line.
            var msg = ex.Message.Split('\n')[0];
            if (payload.Password is { Length: > 0 } pw) msg = msg.Replace(pw, ConnectionStringFactory.Mask);
            return new ConnectionTestResult(false, msg, sw.Elapsed.TotalMilliseconds);
        }
    }
}

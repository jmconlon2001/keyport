using System.Xml.Linq;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Keyport.Core.Crypto;
using Keyport.Server.Configuration;
using Keyport.Server.Data;
using Keyport.Server.Edge;
using Keyport.Server.Services;

namespace Keyport.Server;

/// <summary>Command-line operations that run instead of the web server.</summary>
public static class Cli
{
    public static bool IsCommand(string[] args) =>
        args.Contains("--healthcheck") || args.Contains("--bootstrap-password") || args.Contains("--generate-master-key") || args.Contains("--rotate-kek") || args.Contains("--help") || args.Contains("--seed-demo");

    public static async Task<int> RunAsync(string[] args)
    {
        if (args.Contains("--help"))
        {
            Console.WriteLine("""
                Keyport.Server [options]
                  (no options)                 run the server
                  --healthcheck                exit 0 if the local server is live (for container HEALTHCHECK)
                  --generate-master-key        print a new random 256-bit master key (base64)
                  --bootstrap-password         print the first admin's one-time password (until it is changed)
                  --seed-demo                  EMPTY instance only: load fictional demo data, then run the server
                  --rotate-kek <newKeyFile>    re-wrap all data under a new master key, then exit.
                                               Stop the server first; afterwards point KEYPORT_MASTER_KEY_FILE at the new key.
                """);
            return 0;
        }

        if (args.Contains("--seed-demo"))
            return await DemoSeeder.RunAsync(args);

        if (args.Contains("--generate-master-key"))
        {
            Console.WriteLine(MasterKey.GenerateBase64());
            return 0;
        }

        if (args.Contains("--healthcheck"))
            return await HealthcheckAsync(args);

        if (args.Contains("--bootstrap-password"))
        {
            var o = LoadOptions(args.Where(a => a != "--bootstrap-password").ToArray());
            var path = BootstrapAdmin.PathFor(o);
            if (!File.Exists(path))
            {
                Console.Error.WriteLine("No one-time password is pending (it was already changed, or one was supplied with Keyport:BootstrapAdminPasswordFile).");
                return 1;
            }
            Console.Write(File.ReadAllText(path));
            return 0;
        }

        var idx = Array.IndexOf(args, "--rotate-kek");
        if (idx < 0 || idx + 1 >= args.Length)
        {
            Console.Error.WriteLine("--rotate-kek requires the path of the new key file.");
            return 2;
        }
        return await RotateKekAsync(args.Where((_, i) => i != idx && i != idx + 1).ToArray(), args[idx + 1]);
    }

    private static KeyportOptions LoadOptions(string[] args)
    {
        var config = new ConfigurationBuilder()
            .AddJsonFile("appsettings.json", optional: true)
            .AddJsonFile($"appsettings.{Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") ?? "Production"}.json", optional: true)
            .AddEnvironmentVariables()
            .AddCommandLine(args)
            .Build();
        config = new ConfigurationBuilder().AddConfiguration(config).AddInMemoryCollection(KeyportOptions.LegacyOverrides(config)).Build();
        return config.GetSection(KeyportOptions.Section).Get<KeyportOptions>() ?? new();
    }

    private static async Task<int> HealthcheckAsync(string[] args)
    {
        var o = LoadOptions(args.Where(a => a != "--healthcheck").ToArray());

        // Prefer the plain-HTTP bootstrap port; otherwise use the admin port and skip cert validation (loopback only).
        var url = o.Edge.HttpPort > 0 ? $"http://127.0.0.1:{o.Edge.HttpPort}/health/live" : $"https://127.0.0.1:{o.Edge.AdminPort}/health/live";
        using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };
        using var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        try
        {
            var res = await http.GetAsync(url);
            return res.IsSuccessStatusCode ? 0 : 1;
        }
        catch
        {
            return 1;
        }
    }

    private static async Task<int> RotateKekAsync(string[] args, string newKeyFile)
    {
        using var newKek = MasterKey.LoadFromFile(newKeyFile);
        var app = KeyportApp.Build(args);
        var options = app.Services.GetRequiredService<IOptions<KeyportOptions>>().Value;
        var current = app.Services.GetRequiredService<EnvelopeEncryptor>();
        if (current.KeyId == newKek.KeyId)
        {
            Console.Error.WriteLine("The new key is the same as the current key.");
            return 2;
        }

        await using var scope = app.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
        await db.Database.MigrateAsync();

        await using var tx = await db.Database.BeginTransactionAsync();
        var count = await SecretService.RewrapAllAsync(db, current, newKek);
        var tokenCount = await ProtectedTokens.RewrapAllAsync(db, current, newKek);

        // CA keys and data-protection keys are files; back them up so a failure can be rolled back by hand.
        var backup = Path.Combine(options.DataPath, $"kek-rotation-backup-{DateTime.UtcNow:yyyyMMddHHmmss}");
        Directory.CreateDirectory(backup);
        foreach (var dir in new[] { "ca", "dp-keys" })
        {
            var src = Path.Combine(options.DataPath, dir);
            if (!Directory.Exists(src)) continue;
            Directory.CreateDirectory(Path.Combine(backup, dir));
            foreach (var f in Directory.GetFiles(src)) File.Copy(f, Path.Combine(backup, dir, Path.GetFileName(f)));
        }

        app.Services.GetRequiredService<CertificateManager>().RewrapKeys(newKek);
        var dpCount = RewrapDataProtectionKeys(Path.Combine(options.DataPath, "dp-keys"), current, newKek);
        await tx.CommitAsync();

        await app.Services.GetRequiredService<AuditService>().WriteAsync("system", "kek.rotate", AuditResult.Success,
            details: $"{current.KeyId} -> {newKek.KeyId}; {count} secret versions, {tokenCount} authenticator tokens, {dpCount} data-protection keys");

        Console.WriteLine($"Re-wrapped {count} secret versions, CA keys and {dpCount} data-protection keys under key {newKek.KeyId}.");
        Console.WriteLine($"Backup of previous key files: {backup}");
        Console.WriteLine("Now replace the master key secret with the new key and start the server.");
        return 0;
    }

    private static int RewrapDataProtectionKeys(string dir, EnvelopeEncryptor current, MasterKey newKek)
    {
        if (!Directory.Exists(dir)) return 0;
        var next = new EnvelopeEncryptor(newKek);
        var n = 0;
        foreach (var file in Directory.GetFiles(dir, "*.xml"))
        {
            var doc = XDocument.Load(file);
            foreach (var enc in doc.Descendants("kekEncrypted").ToList())
            {
                var plain = new KekXmlDecryptor(new SingleServiceProvider(current)).Decrypt(enc);
                var reEncrypted = new KekXmlEncryptor(next).Encrypt(plain).EncryptedElement;
                enc.ReplaceWith(reEncrypted);
                n++;
            }
            doc.Save(file);
        }
        return n;
    }

    private sealed class SingleServiceProvider(EnvelopeEncryptor e) : IServiceProvider
    {
        public object? GetService(Type serviceType) => serviceType == typeof(EnvelopeEncryptor) ? e : null;
    }
}

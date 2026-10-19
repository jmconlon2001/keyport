using Keyport.Server.Configuration;

namespace Keyport.Server.Services;

/// <summary>
/// The first administrator's one-time password. It is never written to the log (logs are often shipped and kept);
/// it goes to <c>{DataPath}/bootstrap-admin.txt</c>, readable only by the Keyport user, and the file is deleted as soon
/// as that password is changed. Read it with <c>podman exec keyport dotnet Keyport.Server.dll --bootstrap-password</c>.
/// Alternatively supply it yourself with <c>Keyport:BootstrapAdminPasswordFile</c> (e.g. a container secret).
/// </summary>
public static class BootstrapAdmin
{
    public const string FileName = "bootstrap-admin.txt";

    public static string PathFor(KeyportOptions o) => Path.Combine(o.DataPath, FileName);

    /// <summary>The password to create the first admin with: the configured file's content, or a new random one.</summary>
    public static (string Password, bool Supplied) ChoosePassword(KeyportOptions o)
    {
        if (!string.IsNullOrWhiteSpace(o.BootstrapAdminPasswordFile))
        {
            var supplied = File.ReadAllText(o.BootstrapAdminPasswordFile).Trim();
            if (supplied.Length < 12) throw new InvalidOperationException($"{o.BootstrapAdminPasswordFile} must contain a password of at least 12 characters.");
            return (supplied, true);
        }
        return (Core.Crypto.PasswordGenerator.Generate(20), false);
    }

    public static void Save(KeyportOptions o, string user, string password)
    {
        var path = PathFor(o);
        var content = $"user: {user}\npassword: {password}\n\nChange this password at first sign-in; this file is then deleted.\n";
        if (OperatingSystem.IsWindows()) File.WriteAllText(path, content);
        else
        {
            using var stream = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.Create, Access = FileAccess.Write, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite,
            });
            using var writer = new StreamWriter(stream);
            writer.Write(content);
        }
    }

    public static void Forget(KeyportOptions o)
    {
        try { File.Delete(PathFor(o)); } catch (IOException) { } catch (UnauthorizedAccessException) { }
    }
}

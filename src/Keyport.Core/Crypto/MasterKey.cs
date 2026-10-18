using System.Security.Cryptography;
using System.Text;

namespace Keyport.Core.Crypto;

/// <summary>
/// The key-encryption key (KEK). Loaded from a file (Docker secret) and never persisted by the app.
/// Accepted file formats: 32 raw bytes, or 32 bytes encoded as base64 or hex (whitespace ignored).
/// </summary>
public sealed class MasterKey : IDisposable
{
    public const int KeySize = 32;

    private readonly byte[] _key;

    public MasterKey(byte[] key)
    {
        if (key.Length != KeySize)
            throw new ArgumentException($"Master key must be exactly {KeySize} bytes (got {key.Length}).", nameof(key));
        _key = (byte[])key.Clone();
        KeyId = Convert.ToHexString(SHA256.HashData(Concat("sm-kek-id"u8, _key)))[..16].ToLowerInvariant();
    }

    /// <summary>Non-secret identifier for this key (truncated hash), stored next to wrapped data to detect key mismatches.</summary>
    public string KeyId { get; }

    internal ReadOnlySpan<byte> Bytes => _key;

    public static MasterKey LoadFromFile(string path)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException(
                $"Master key file '{path}' not found. Provide a 32-byte key via a Docker secret (keyport_master_key) or KEYPORT_MASTER_KEY_FILE.", path);

        var raw = File.ReadAllBytes(path);
        if (raw.Length == KeySize)
            return new MasterKey(raw);

        var text = Encoding.ASCII.GetString(raw).Trim();
        text = new string(text.Where(c => !char.IsWhiteSpace(c)).ToArray());

        if (text.Length == KeySize * 2 && text.All(Uri.IsHexDigit))
            return new MasterKey(Convert.FromHexString(text));

        try
        {
            var decoded = Convert.FromBase64String(text);
            if (decoded.Length == KeySize)
                return new MasterKey(decoded);
        }
        catch (FormatException) { }

        throw new InvalidDataException(
            $"Master key file '{path}' must contain 32 raw bytes, 64 hex chars, or base64 of 32 bytes. Generate one with: openssl rand -base64 32");
    }

    public static string GenerateBase64() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(KeySize));

    public void Dispose() => CryptographicOperations.ZeroMemory(_key);

    private static byte[] Concat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var r = new byte[a.Length + b.Length];
        a.CopyTo(r);
        b.CopyTo(r.AsSpan(a.Length));
        return r;
    }
}

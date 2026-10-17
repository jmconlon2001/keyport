using System.Security.Cryptography;
using System.Text;

namespace SecretManager.Core.Crypto;

/// <summary>A freshly generated API key. <see cref="Plaintext"/> is shown to the user exactly once.</summary>
public sealed record GeneratedApiKey(string Prefix, string Plaintext, string Hash);

/// <summary>
/// API key format: <c>sm_{prefix}_{secret}</c>. The prefix (8 chars) is a public lookup id; the secret is
/// 256 bits of randomness. Only SHA-256(key) is stored. A slow hash is unnecessary because the key is not
/// guessable (unlike a human password).
/// </summary>
public static class ApiKeys
{
    private const string Alphabet = "abcdefghijkmnopqrstuvwxyz23456789";
    private const string SecretAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    public static GeneratedApiKey Generate()
    {
        var prefix = RandomNumberGenerator.GetString(Alphabet, 8);
        // 43 chars from a 62-char alphabet ≈ 256 bits.
        var secret = RandomNumberGenerator.GetString(SecretAlphabet, 43);
        var key = $"sm_{prefix}_{secret}";
        return new GeneratedApiKey(prefix, key, Hash(key));
    }

    public static string Hash(string key) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

    public static bool TryParsePrefix(string key, out string prefix)
    {
        prefix = "";
        var parts = key.Split('_');
        if (parts.Length != 3 || parts[0] != "sm" || parts[1].Length != 8 || parts[2].Length < 32)
            return false;
        prefix = parts[1];
        return true;
    }

    public static bool Verify(string key, string storedHash) =>
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(Hash(key)),
            Encoding.ASCII.GetBytes(storedHash));
}

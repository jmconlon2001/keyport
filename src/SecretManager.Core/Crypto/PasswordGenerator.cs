using System.Security.Cryptography;

namespace SecretManager.Core.Crypto;

public static class PasswordGenerator
{
    private const string Upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Lower = "abcdefghijkmnopqrstuvwxyz";
    private const string Digits = "23456789";
    // Deliberately excludes characters that need escaping in connection strings: ; = ' " { } and space.
    private const string Symbols = "!#$%*+-.:?@^_~";

    /// <summary>Cryptographically random password containing at least one of each enabled character class.</summary>
    public static string Generate(int length = 24, bool symbols = true)
    {
        length = Math.Clamp(length, 12, 128);
        var classes = symbols ? new[] { Upper, Lower, Digits, Symbols } : new[] { Upper, Lower, Digits };
        var all = string.Concat(classes);

        var chars = new char[length];
        for (var i = 0; i < classes.Length; i++)
            chars[i] = classes[i][RandomNumberGenerator.GetInt32(classes[i].Length)];
        for (var i = classes.Length; i < length; i++)
            chars[i] = all[RandomNumberGenerator.GetInt32(all.Length)];

        RandomNumberGenerator.Shuffle(chars.AsSpan());
        return new string(chars);
    }
}

using System.Text.RegularExpressions;

namespace Keyport.Core.Secrets;

public static partial class SecretNames
{
    /// <summary>Path-like names: lowercase segments of [a-z0-9._-] separated by '/', e.g. <c>billing/oracle-main</c>.</summary>
    [GeneratedRegex(@"^[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*$")]
    private static partial Regex NameRegex();

    [GeneratedRegex(@"[^a-z0-9._-]+")]
    private static partial Regex InvalidChars();

    [GeneratedRegex(@"-{2,}")]
    private static partial Regex RepeatedDashes();

    /// <summary>
    /// Turns free text into a valid name segment, e.g. "Billing DB (Prod)" → "billing-db-prod".
    /// Used so non-technical users can type naturally.
    /// </summary>
    public static string Slugify(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return "";
        var s = InvalidChars().Replace(text.Trim().ToLowerInvariant(), "-");
        s = RepeatedDashes().Replace(s, "-").Trim('-', '.', '_');
        return s.Length > 80 ? s[..80].TrimEnd('-') : s;
    }

    /// <summary>Slugifies each "/"-separated part of a folder path, e.g. "Billing / EU" → "billing/eu".</summary>
    public static string SlugifyPath(string? path) =>
        string.Join('/', (path ?? "").Split('/', StringSplitOptions.RemoveEmptyEntries).Select(Slugify).Where(p => p.Length > 0));

    /// <summary>Folders (every ancestor path) present in a set of secret names, e.g. billing, billing/eu.</summary>
    public static IEnumerable<string> Folders(IEnumerable<string> names) =>
        names.SelectMany(n =>
        {
            var parts = n.Split('/');
            return Enumerable.Range(1, parts.Length - 1).Select(i => string.Join('/', parts.Take(i)));
        }).Distinct().Order(StringComparer.Ordinal);

    public static bool IsValid(string? name) => !string.IsNullOrEmpty(name) && name.Length <= 200 && NameRegex().IsMatch(name);

    /// <summary>
    /// Grant patterns: an exact name, <c>prefix/*</c> (everything under prefix, any depth), or <c>*</c> (everything).
    /// </summary>
    public static bool MatchesGrant(string name, string pattern)
    {
        if (pattern == "*") return true;
        if (pattern.EndsWith("/*", StringComparison.Ordinal))
            return name.StartsWith(pattern[..^1], StringComparison.Ordinal);
        return string.Equals(name, pattern, StringComparison.Ordinal);
    }

    public static bool IsValidGrant(string? pattern) =>
        pattern == "*" ||
        (pattern is not null && pattern.EndsWith("/*", StringComparison.Ordinal) ? IsValid(pattern[..^2]) : IsValid(pattern));
}

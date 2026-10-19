using System.Text.RegularExpressions;
using Keyport.Core.Secrets.Renderers;

namespace Keyport.Core.Secrets.Types;

public sealed class SecretTypeDefinitionException(string message) : Exception(message);

/// <summary>
/// All known secret types plus the renderers that build their outputs. Validates definitions when created, and
/// provides the generic operations the UI, API and services use (validation, rendering, masking, promotion).
/// </summary>
public sealed partial class SecretTypeRegistry
{
    public const string Mask = "********";

    /// <summary>The registry in use. Defaults to the built-in types; the server replaces it at startup to add configured types.</summary>
    public static SecretTypeRegistry Current
    {
        get => _current ??= CreateDefault();
        set => _current = value;
    }

    private static SecretTypeRegistry? _current;

    private readonly Dictionary<string, SecretTypeDefinition> _types;
    private readonly Dictionary<string, ISecretRenderer> _renderers;

    public IReadOnlyList<SecretTypeDefinition> All { get; }

    private SecretTypeRegistry(Dictionary<string, SecretTypeDefinition> types, Dictionary<string, ISecretRenderer> renderers, List<SecretTypeDefinition> ordered)
    {
        _types = types;
        _renderers = renderers;
        All = ordered;
    }

    public static IReadOnlyList<ISecretRenderer> BuiltInRenderers { get; } =
        [new SqlServerRenderer(), new OracleRenderer(), new KeyValueRenderer(), new UriRenderer(), new TemplateRenderer(), new PemBundleRenderer()];

    public static SecretTypeRegistry CreateDefault() => Create(BuiltInTypes.All);

    /// <summary>Builds and validates a registry. Later definitions with the same key are rejected (no silent overrides).</summary>
    public static SecretTypeRegistry Create(IEnumerable<SecretTypeDefinition> definitions, IEnumerable<ISecretRenderer>? extraRenderers = null)
    {
        var renderers = BuiltInRenderers.Concat(extraRenderers ?? []).ToDictionary(r => r.Name, StringComparer.OrdinalIgnoreCase);
        var types = new Dictionary<string, SecretTypeDefinition>(StringComparer.OrdinalIgnoreCase);
        var ordered = new List<SecretTypeDefinition>();
        foreach (var d in definitions)
        {
            Validate(d, renderers);
            if (!types.TryAdd(d.Key, d))
                throw new SecretTypeDefinitionException($"Secret type '{d.Key}' is defined more than once ({types[d.Key].Source} and {d.Source}).");
            ordered.Add(d);
        }
        return new SecretTypeRegistry(types, renderers, ordered);
    }

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_-]{1,39}$")]
    private static partial Regex TypeKeyRegex();

    [GeneratedRegex("^[a-z][A-Za-z0-9_]{0,39}$")]
    private static partial Regex FieldKeyRegex();

    /// <summary>Patterns come from type definitions (configuration); a badly written one must not hang a request (ReDoS).</summary>
    private static readonly TimeSpan PatternTimeout = TimeSpan.FromMilliseconds(100);

    private static bool MatchesPattern(string value, string pattern)
    {
        try { return Regex.IsMatch(value, pattern, RegexOptions.CultureInvariant, PatternTimeout); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static readonly HashSet<string> ReservedFieldKeys = new(StringComparer.OrdinalIgnoreCase) { "description", "tags", "name", "type", "environment", "version" };

    private static void Validate(SecretTypeDefinition d, Dictionary<string, ISecretRenderer> renderers)
    {
        string Where() => $"secret type '{d.Key}' ({d.Source})";
        if (!TypeKeyRegex().IsMatch(d.Key ?? ""))
            throw new SecretTypeDefinitionException($"Invalid type key '{d.Key}': use 2-40 letters, digits, '-' or '_', starting with a letter.");
        if (string.IsNullOrWhiteSpace(d.Title))
            throw new SecretTypeDefinitionException($"{Where()} needs a Title.");
        if (!Categories.Order.Contains(d.Category))
            throw new SecretTypeDefinitionException($"{Where()} has unknown category '{d.Category}'. Use one of: {string.Join(", ", Categories.Order)}.");

        var keys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in d.Fields)
        {
            if (!FieldKeyRegex().IsMatch(f.Key ?? ""))
                throw new SecretTypeDefinitionException($"{Where()}: invalid field key '{f.Key}' (camelCase letters/digits).");
            if (ReservedFieldKeys.Contains(f.Key!))
                throw new SecretTypeDefinitionException($"{Where()}: field key '{f.Key}' is reserved.");
            if (!keys.Add(f.Key!))
                throw new SecretTypeDefinitionException($"{Where()}: field '{f.Key}' is defined twice.");
            if (string.IsNullOrWhiteSpace(f.Label))
                throw new SecretTypeDefinitionException($"{Where()}: field '{f.Key}' needs a Label.");
            if (f.Kind == FieldKind.Select && f.Options.Count == 0)
                throw new SecretTypeDefinitionException($"{Where()}: select field '{f.Key}' needs Options.");
            if (f.Pattern is not null)
            {
                try { _ = new Regex(f.Pattern, RegexOptions.CultureInvariant, PatternTimeout); }
                catch (ArgumentException) { throw new SecretTypeDefinitionException($"{Where()}: field '{f.Key}' has an invalid Pattern."); }
            }
        }
        foreach (var f in d.Fields)
        {
            foreach (var u in f.RequiredUnless.Append(f.DisabledWhen ?? "").Where(u => u.Length > 0))
                if (!keys.Contains(u))
                    throw new SecretTypeDefinitionException($"{Where()}: field '{f.Key}' refers to unknown field '{u}'.");
        }
        foreach (var g in d.RequireOneOf)
            foreach (var k in g)
                if (!keys.Contains(k))
                    throw new SecretTypeDefinitionException($"{Where()}: RequireOneOf refers to unknown field '{k}'.");

        var outKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var o in d.Outputs)
        {
            if (string.IsNullOrWhiteSpace(o.Key) || !outKeys.Add(o.Key))
                throw new SecretTypeDefinitionException($"{Where()}: outputs need unique keys.");
            if (!renderers.TryGetValue(o.Renderer, out var r))
                throw new SecretTypeDefinitionException($"{Where()}: output '{o.Key}' uses unknown renderer '{o.Renderer}'. Available: {string.Join(", ", renderers.Keys)}.");
            var err = r.ValidateSettings(o.Settings, keys);
            if (err is not null)
                throw new SecretTypeDefinitionException($"{Where()}: output '{o.Key}': {err}");
        }
    }

    public SecretTypeDefinition? Find(string? key) => key is not null && _types.TryGetValue(key, out var d) ? d : null;

    /// <summary>The definition, or a read-only placeholder for keys with no definition (e.g. removed from configuration).</summary>
    public SecretTypeDefinition Get(string? key) => Find(key) ?? new SecretTypeDefinition
    {
        Key = key ?? "",
        Title = $"Unknown type ({key})",
        Description = "This type is no longer defined. Its secrets are still stored and served, but can't be edited.",
        Icon = "alert",
        IsUnknown = true,
        Source = "unknown",
    };

    public IEnumerable<IGrouping<string, SecretTypeDefinition>> ByCategory() =>
        All.GroupBy(d => d.Category).OrderBy(g => Array.IndexOf(Categories.Order, g.Key));

    // ---------------- Generic operations ----------------

    /// <summary>Whether a field currently applies (not disabled by a boolean toggle such as Windows authentication).</summary>
    public static bool IsActive(FieldDefinition f, IReadOnlyDictionary<string, string?> values) =>
        f.DisabledWhen is null || !SecretFields.IsTrue(values.GetValueOrDefault(f.DisabledWhen));

    private static bool IsSet(IReadOnlyDictionary<string, string?> values, string key) =>
        values.TryGetValue(key, out var v) && !string.IsNullOrEmpty(v) && !string.Equals(v, "false", StringComparison.OrdinalIgnoreCase);

    public static bool IsRequiredNow(FieldDefinition f, IReadOnlyDictionary<string, string?> values) =>
        f.Required && IsActive(f, values) && !f.RequiredUnless.Any(u => IsSet(values, u));

    /// <summary>Labels of required fields that are still empty (for "Still needed" hints). Sensitive fields only when checked.</summary>
    public List<string> Missing(SecretTypeDefinition d, IReadOnlyDictionary<string, string?> values, bool includeSensitive)
    {
        var missing = new List<string>();
        foreach (var f in d.Fields.Where(f => includeSensitive || !f.Sensitive))
            if (IsRequiredNow(f, values) && !IsSet(values, f.Key) && f.Kind != FieldKind.Bool)
                missing.Add(f.Label);
        foreach (var g in d.RequireOneOf)
        {
            var fields = g.Select(k => d.Field(k)!).ToList();
            if (fields.Any(f => f.Sensitive && !includeSensitive)) continue;
            var relaxed = d.Fields.Where(f => f.IsOverride).Any(f => IsSet(values, f.Key));
            if (!relaxed && !g.Any(k => IsSet(values, k)))
                missing.Add(string.Join(" or ", fields.Select(f => f.Label)));
        }
        return missing;
    }

    /// <summary>Full validation before saving. Returns plain-language errors (empty when valid).</summary>
    public List<string> Validate(SecretTypeDefinition d, IReadOnlyDictionary<string, string?> values, bool includeSensitive = true)
    {
        var errors = Missing(d, values, includeSensitive).Select(l => $"{l} is required.").ToList();
        foreach (var f in d.Fields)
        {
            if (!includeSensitive && f.Sensitive) continue;
            var v = values.GetValueOrDefault(f.Key);
            if (string.IsNullOrEmpty(v) || !IsActive(f, values)) continue;
            var err = ValidateValue(f, v);
            if (err is not null) errors.Add(err);
        }
        if (errors.Count > 0 || !includeSensitive) return errors;

        foreach (var o in d.Outputs)
        {
            try
            {
                var rendered = Render(d, o, values);
                var err = _renderers[o.Renderer].Validate(o, values, rendered);
                if (err is not null) errors.Add($"{o.Label}: {err}");
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or KeyNotFoundException or InvalidOperationException)
            {
                errors.Add($"{o.Label}: {ex.Message}");
            }
        }
        return errors;
    }

    private static string? ValidateValue(FieldDefinition f, string v)
    {
        switch (f.Kind)
        {
            case FieldKind.Port:
                if (!int.TryParse(v, out var p) || p is < 1 or > 65535) return $"{f.Label} must be a port between 1 and 65535.";
                break;
            case FieldKind.Number:
                if (!long.TryParse(v, out var n)) return $"{f.Label} must be a number.";
                if (f.Min is { } min && n < min) return $"{f.Label} must be at least {min}.";
                if (f.Max is { } max && n > max) return $"{f.Label} must be at most {max}.";
                break;
            case FieldKind.Url:
                if (!Uri.TryCreate(v, UriKind.Absolute, out _)) return $"{f.Label} must be a full address, e.g. https://example.com.";
                break;
            case FieldKind.Select:
                if (!f.Options.Contains(v, StringComparer.OrdinalIgnoreCase)) return $"{f.Label} must be one of: {string.Join(", ", f.Options)}.";
                break;
            case FieldKind.Bool:
                if (v is not ("true" or "false")) return $"{f.Label} must be true or false.";
                break;
            case FieldKind.Pem:
                if (!v.Contains("-----BEGIN ") || !v.Contains("-----END ")) return $"{f.Label} must be in PEM format (-----BEGIN … -----END …).";
                break;
        }
        if (f.Pattern is not null && !MatchesPattern(v, f.Pattern)) return $"{f.Label} has an invalid format.";
        if (f.Kind is not (FieldKind.Number or FieldKind.Port) && f.Max is { } len && v.Length > len) return $"{f.Label} is too long (max {len}).";
        return null;
    }

    /// <summary>Renders one output. Fields disabled by a toggle are left out; an override field, when set, replaces the result.</summary>
    public string Render(SecretTypeDefinition d, OutputDefinition o, IReadOnlyDictionary<string, string?> values)
    {
        if (o.Settings.TryGetValue("overrideField", out var ov) && values.GetValueOrDefault(ov) is { Length: > 0 } overridden)
            return overridden;
        var active = values.Where(kv => d.Field(kv.Key) is not { } f || IsActive(f, values))
            .ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
        return _renderers[o.Renderer].Render(o, active);
    }

    public Dictionary<string, string> RenderAll(SecretTypeDefinition d, IReadOnlyDictionary<string, string?> values) =>
        d.Outputs.ToDictionary(o => o.Key, o => Render(d, o, values));

    /// <summary>Outputs with every sensitive value replaced by a mask, for previews. Never throws.</summary>
    public Dictionary<string, string> RenderMasked(SecretTypeDefinition d, IReadOnlyDictionary<string, string?> values)
    {
        var masked = values.ToDictionary(kv => kv.Key, kv => kv.Value, StringComparer.OrdinalIgnoreCase);
        foreach (var f in d.SensitiveFields)
            if (!string.IsNullOrEmpty(masked.GetValueOrDefault(f.Key)) && !f.IsOverride && !f.CopyOnPromote)
                masked[f.Key] = f.Kind == FieldKind.Pem ? "-----BEGIN (hidden)-----\n" + Mask + "\n-----END (hidden)-----" : Mask;

        var result = new Dictionary<string, string>();
        foreach (var o in d.Outputs)
        {
            try
            {
                if (o.Settings.TryGetValue("overrideField", out var ov) && masked.GetValueOrDefault(ov) is { Length: > 0 } overridden)
                {
                    result[o.Key] = ConnectionStringFactory.MaskPassword(overridden);
                    continue;
                }
                // URL renderers percent-encode the mask; show it as the plain mask again.
                result[o.Key] = Render(d, o, masked).Replace(Uri.EscapeDataString(Mask), Mask);
            }
            catch (Exception)
            {
                result[o.Key] = "Fill in the details to see a preview.";
            }
        }
        return result;
    }

    /// <summary>Values carried over when a secret is copied to another environment: clear fields plus fields marked CopyOnPromote.</summary>
    public static (SecretMetadata Clear, SecretPayload Sensitive) ForPromotion(SecretTypeDefinition d, SecretMetadata clear, SecretPayload sensitive)
    {
        var copy = new SecretPayload();
        foreach (var f in d.SensitiveFields.Where(f => f.CopyOnPromote))
            copy[f.Key] = sensitive[f.Key];
        return (clear.Clone(), copy);
    }

    /// <summary>Splits one value bag into clear and sensitive parts by the definition; undefined keys are dropped.</summary>
    public static (SecretMetadata Clear, SecretPayload Sensitive) Split(SecretTypeDefinition d, IReadOnlyDictionary<string, string?> values, string? description)
    {
        var clear = new SecretMetadata { Description = description };
        var sensitive = new SecretPayload();
        foreach (var f in d.Fields)
        {
            var v = values.GetValueOrDefault(f.Key);
            if (f.Sensitive) sensitive[f.Key] = v;
            else clear[f.Key] = v;
        }
        return (clear, sensitive);
    }

    /// <summary>The renderer-specific parse check used by the legacy ConnectionStringFactory API.</summary>
    internal ISecretRenderer Renderer(string name) => _renderers[name];
}

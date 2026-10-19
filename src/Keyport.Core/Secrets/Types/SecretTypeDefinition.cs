namespace Keyport.Core.Secrets.Types;

public enum FieldKind
{
    Text,
    Number,
    Port,
    Bool,
    Select,
    Password,
    Multiline,
    Url,
    Host,
    Pem,
}

public static class OutputKeys
{
    public const string ConnectionString = "connectionString";
}

public static class Categories
{
    public const string Database = "database";
    public const string Login = "login";
    public const string Key = "key";
    public const string Certificate = "certificate";
    public const string Messaging = "messaging";
    public const string Cloud = "cloud";
    public const string Other = "other";

    public static string Title(string category) => category switch
    {
        Database => "Databases",
        Messaging => "Messaging and caches",
        Login => "Logins and accounts",
        Key => "Keys and tokens",
        Certificate => "Certificates",
        Cloud => "Cloud credentials",
        _ => "Other",
    };

    public static readonly string[] Order = [Database, Messaging, Login, Key, Certificate, Cloud, Other];
}

/// <summary>One input of a secret type. Settable properties so definitions can also come from configuration/JSON.</summary>
public sealed class FieldDefinition
{
    public string Key { get; set; } = "";
    public string Label { get; set; } = "";
    public FieldKind Kind { get; set; } = FieldKind.Text;

    /// <summary>Stored in the encrypted payload (true) or as clear metadata (false).</summary>
    public bool Sensitive { get; set; }

    public bool Required { get; set; }

    /// <summary>Not required when any of these fields is set (non-empty and not "false"), e.g. a connection-string override.</summary>
    public List<string> RequiredUnless { get; set; } = [];

    /// <summary>Hidden/ignored when this boolean field is true (e.g. username when Windows authentication is on).</summary>
    public string? DisabledWhen { get; set; }

    public string? Help { get; set; }
    public string? Placeholder { get; set; }
    public string? Default { get; set; }
    public List<string> Options { get; set; } = [];

    /// <summary>Shown under "Advanced settings".</summary>
    public bool Advanced { get; set; }

    /// <summary>Copied when a secret is copied to another environment. Sensitive fields are never copied unless set.</summary>
    public bool CopyOnPromote { get; set; }

    /// <summary>Offer the strong-password generator.</summary>
    public bool Generate { get; set; }

    /// <summary>Optional regular expression the value must match.</summary>
    public string? Pattern { get; set; }
    public int? Min { get; set; }
    public int? Max { get; set; }

    /// <summary>Recommended rather than required (shown as a hint).</summary>
    public bool Recommended { get; set; }

    /// <summary>Kept whole when this field changes (e.g. the full connection-string override).</summary>
    public bool IsOverride { get; set; }
}

/// <summary>Something the application receives, built from the fields by a named renderer.</summary>
public sealed class OutputDefinition
{
    public string Key { get; set; } = "";
    public string Label { get; set; } = "";

    /// <summary>Renderer name: sqlserver, oracle, keyvalue, uri, template, pem-bundle.</summary>
    public string Renderer { get; set; } = "template";

    public Dictionary<string, string> Settings { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Describes one kind of secret: its fields, what applications receive, and how to test it.</summary>
public sealed class SecretTypeDefinition
{
    /// <summary>Stable identifier stored with each secret. Never change it once secrets exist.</summary>
    public string Key { get; set; } = "";
    public string Title { get; set; } = "";
    public string Description { get; set; } = "";

    /// <summary>Icon name from the UI icon set (database, globe, user, key, award, code, server, lock, link).</summary>
    public string Icon { get; set; } = "key";

    /// <summary>Accent colour for the type's icon.</summary>
    public string Color { get; set; } = "#64748b";

    public string Category { get; set; } = Categories.Other;
    public List<FieldDefinition> Fields { get; set; } = [];
    public List<OutputDefinition> Outputs { get; set; } = [];

    /// <summary>At least one field of each group must be set, e.g. ["serviceName","sid"].</summary>
    public List<List<string>> RequireOneOf { get; set; } = [];

    /// <summary>Connection test to offer: sqlserver, oracle, tcp, or null for none.</summary>
    public string? Tester { get; set; }

    /// <summary>Where the definition came from (built-in, configuration or a file); informational.</summary>
    public string Source { get; set; } = "built-in";

    /// <summary>True for the placeholder returned for a type key that has no definition.</summary>
    public bool IsUnknown { get; set; }

    public FieldDefinition? Field(string key) => Fields.FirstOrDefault(f => string.Equals(f.Key, key, StringComparison.OrdinalIgnoreCase));
    public bool HasOutput(string key) => Outputs.Any(o => string.Equals(o.Key, key, StringComparison.OrdinalIgnoreCase));
    public bool HasUsernameAndPassword => Field("username") is not null && Field("password") is not null;
    public IEnumerable<FieldDefinition> SensitiveFields => Fields.Where(f => f.Sensitive);
    public IEnumerable<FieldDefinition> ClearFields => Fields.Where(f => !f.Sensitive);
}

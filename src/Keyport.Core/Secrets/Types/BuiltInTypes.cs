namespace Keyport.Core.Secrets.Types;

/// <summary>
/// Secret types that ship with Keyport. The first five keep the keys and field names used before types were
/// pluggable, so existing secrets load unchanged. Add more here, or define them in configuration (no code needed).
/// </summary>
public static class BuiltInTypes
{
    // ---- small builders to keep the catalog readable ----
    private static FieldDefinition F(string key, string label, FieldKind kind = FieldKind.Text, bool sensitive = false, bool required = false,
        string? help = null, string? placeholder = null, string? @default = null, bool advanced = false, bool copy = false, bool generate = false,
        string[]? options = null, string[]? unless = null, string? disabledWhen = null, string? pattern = null, bool recommended = false, bool isOverride = false) => new()
    {
        Key = key, Label = label, Kind = kind, Sensitive = sensitive, Required = required, Help = help, Placeholder = placeholder,
        Default = @default, Advanced = advanced, CopyOnPromote = copy, Generate = generate, Options = [.. options ?? []],
        RequiredUnless = [.. unless ?? []], DisabledWhen = disabledWhen, Pattern = pattern, Recommended = recommended, IsOverride = isOverride,
    };

    private static OutputDefinition O(string key, string label, string renderer, params (string Key, string Value)[] settings) => new()
    {
        Key = key, Label = label, Renderer = renderer,
        Settings = settings.ToDictionary(s => s.Key, s => s.Value, StringComparer.OrdinalIgnoreCase),
    };

    private const string Override = "connectionStringOverride";
    private static readonly string[] UnlessOverride = [Override];

    private static FieldDefinition Username(string? placeholder = "e.g. svc_billing", bool required = true, string[]? unless = null, string? disabledWhen = null) =>
        F("username", "Username", sensitive: true, required: required, copy: true, placeholder: placeholder, unless: unless, disabledWhen: disabledWhen);

    private static FieldDefinition Password(bool required = true, string[]? unless = null, string? disabledWhen = null, bool generate = true) =>
        F("password", "Password", FieldKind.Password, sensitive: true, required: required, generate: generate, unless: unless, disabledWhen: disabledWhen,
          help: generate ? "Paste the password you were given, or press Generate to create a strong one. If you generate one, remember to set it on the database or system too." : null);

    private static FieldDefinition ExtraOptions(string placeholder) =>
        F("extraOptions", "Additional driver options", advanced: true, placeholder: placeholder);

    private static FieldDefinition ConnectionOverride() =>
        F(Override, "Full connection string (replaces everything above)", FieldKind.Multiline, sensitive: true, advanced: true, isOverride: true,
          placeholder: "Leave empty unless you were given a complete connection string");

    public static IReadOnlyList<SecretTypeDefinition> All { get; } =
    [
        // ===================== original five (keys and field names must not change) =====================
        new()
        {
            Key = "OracleConnection", Title = "Oracle database", Category = Categories.Database, Icon = "database", Color = "#ef4444",
            Description = "Server, service name and login for an Oracle database.",
            Fields =
            [
                F("host", "Server name", FieldKind.Host, required: true, unless: UnlessOverride, placeholder: "e.g. ora-prod-01.corp.local", help: "The host name or IP address of the database server."),
                F("port", "Port", FieldKind.Port, placeholder: "1521", help: "Leave blank for the usual 1521."),
                F("serviceName", "Service name", placeholder: "e.g. BILLPDB", help: "The Oracle service the application connects to. Older databases may use a SID instead (under Advanced settings)."),
                F("sid", "SID", advanced: true, help: "Only for older databases without a service name."),
                F("useTnsDescriptor", "Use full TNS descriptor", FieldKind.Bool, advanced: true),
                ExtraOptions("Pooling=true;Max Pool Size=50"),
                Username(unless: UnlessOverride),
                Password(unless: UnlessOverride),
                ConnectionOverride(),
            ],
            RequireOneOf = [["serviceName", "sid"]],
            Outputs = [O(OutputKeys.ConnectionString, "Connection string", "oracle", ("overrideField", Override))],
            Tester = "oracle",
        },
        new()
        {
            Key = "SqlServerConnection", Title = "SQL Server database", Category = Categories.Database, Icon = "database", Color = "#3b82f6",
            Description = "Server, database and login for a Microsoft SQL Server database.",
            Fields =
            [
                F("host", "Server name", FieldKind.Host, required: true, unless: UnlessOverride, placeholder: "e.g. sql-prod-01.corp.local", help: "Include the instance if there is one, e.g. sql-01\\REPORTING."),
                F("port", "Port", FieldKind.Port, placeholder: "1433", help: "Leave blank for the usual 1433."),
                F("database", "Database name", placeholder: "e.g. Billing", recommended: true),
                F("encrypt", "Encryption", FieldKind.Select, advanced: true, @default: "Mandatory", options: ["Mandatory", "Strict", "Optional"]),
                F("applicationName", "Application name", advanced: true),
                F("trustServerCertificate", "Trust server certificate", FieldKind.Bool, advanced: true),
                F("integratedSecurity", "Windows authentication (no password)", FieldKind.Bool, advanced: true),
                ExtraOptions("MultipleActiveResultSets=True;Connect Timeout=30"),
                Username(unless: UnlessOverride, disabledWhen: "integratedSecurity"),
                Password(unless: UnlessOverride, disabledWhen: "integratedSecurity"),
                ConnectionOverride(),
            ],
            Outputs = [O(OutputKeys.ConnectionString, "Connection string", "sqlserver", ("overrideField", Override))],
            Tester = "sqlserver",
        },
        new()
        {
            Key = "BasicAuth", Title = "Website or API login", Category = Categories.Login, Icon = "globe", Color = "#10b981",
            Description = "A username and password used to sign in to a website or web service.",
            Fields =
            [
                F("url", "Website or API address", FieldKind.Url, placeholder: "e.g. https://api.partner.example"),
                Username(placeholder: "e.g. integration-user"),
                Password(generate: true),
            ],
        },
        new()
        {
            Key = "ServiceAccount", Title = "Service account", Category = Categories.Login, Icon = "user", Color = "#8b5cf6",
            Description = "A Windows / Active Directory account that a program or scheduled job runs as.",
            Fields =
            [
                F("domain", "Domain", placeholder: "e.g. CORP", help: "The part before the \\ in CORP\\svc_batch."),
                F("url", "Used by", placeholder: "e.g. Nightly invoice job"),
                Username(placeholder: "e.g. svc_batch"),
                Password(),
            ],
        },
        new()
        {
            Key = "Generic", Title = "Other secret", Category = Categories.Key, Icon = "key", Color = "#64748b",
            Description = "Any other value, such as an API token or licence key.",
            Fields = [F("value", "Value", FieldKind.Multiline, sensitive: true, required: true)],
        },

        // ===================== databases =====================
        new()
        {
            Key = "PostgresConnection", Title = "PostgreSQL database", Category = Categories.Database, Icon = "database", Color = "#336791",
            Description = "Server, database and login for a PostgreSQL database.",
            Fields =
            [
                F("host", "Server name", FieldKind.Host, required: true, placeholder: "e.g. pg-prod-01.corp.local"),
                F("port", "Port", FieldKind.Port, placeholder: "5432", help: "Leave blank for the usual 5432."),
                F("database", "Database name", required: true, placeholder: "e.g. billing"),
                F("sslMode", "SSL mode", FieldKind.Select, advanced: true, @default: "Require", options: ["Disable", "Prefer", "Require", "VerifyCA", "VerifyFull"]),
                ExtraOptions("Pooling=true;Maximum Pool Size=50"),
                Username(placeholder: "e.g. billing_app"),
                Password(),
            ],
            Outputs =
            [
                O(OutputKeys.ConnectionString, "Connection string", "keyvalue",
                  ("map", "Host=host;Port=port;Database=database;Username=username;Password=password;SSL Mode=sslMode"), ("extraField", "extraOptions")),
                O("url", "Connection URL", "uri", ("scheme", "postgresql"), ("port", "port"), ("path", "database"), ("user", "username"), ("password", "password")),
            ],
            Tester = "tcp",
        },
        new()
        {
            Key = "MySqlConnection", Title = "MySQL / MariaDB database", Category = Categories.Database, Icon = "database", Color = "#00758f",
            Description = "Server, database and login for a MySQL or MariaDB database.",
            Fields =
            [
                F("host", "Server name", FieldKind.Host, required: true, placeholder: "e.g. mysql-prod-01.corp.local"),
                F("port", "Port", FieldKind.Port, placeholder: "3306", help: "Leave blank for the usual 3306."),
                F("database", "Database name", required: true),
                F("sslMode", "SSL mode", FieldKind.Select, advanced: true, @default: "Required", options: ["None", "Preferred", "Required", "VerifyCA", "VerifyFull"]),
                ExtraOptions("Pooling=true;Maximum Pool Size=50"),
                Username(),
                Password(),
            ],
            Outputs =
            [
                O(OutputKeys.ConnectionString, "Connection string", "keyvalue",
                  ("map", "Server=host;Port=port;Database=database;User ID=username;Password=password;SslMode=sslMode"), ("extraField", "extraOptions")),
            ],
            Tester = "tcp",
        },
        new()
        {
            Key = "MongoDbConnection", Title = "MongoDB database", Category = Categories.Database, Icon = "database", Color = "#13aa52",
            Description = "Servers, database and login for MongoDB.",
            Fields =
            [
                F("hosts", "Server(s)", required: true, placeholder: "e.g. mongo-1:27017,mongo-2:27017", help: "One or more host:port pairs, separated by commas."),
                F("database", "Database name", placeholder: "e.g. telemetry"),
                F("tls", "Use TLS", FieldKind.Bool, @default: "true"),
                F("authSource", "Authentication database", advanced: true, @default: "admin"),
                F("replicaSet", "Replica set", advanced: true),
                Username(),
                Password(),
            ],
            Outputs =
            [
                O(OutputKeys.ConnectionString, "Connection string", "uri", ("scheme", "mongodb"), ("host", "hosts"), ("hostIsList", "true"), ("path", "database"),
                  ("user", "username"), ("password", "password"), ("query", "authSource=authSource&replicaSet=replicaSet&tls=tls")),
            ],
        },

        // ===================== messaging and caches =====================
        new()
        {
            Key = "RedisConnection", Title = "Redis cache", Category = Categories.Messaging, Icon = "zap", Color = "#dc382d",
            Description = "Address and password for a Redis server.",
            Fields =
            [
                F("host", "Server name", FieldKind.Host, required: true, placeholder: "e.g. redis-prod.corp.local"),
                F("port", "Port", FieldKind.Port, placeholder: "6379", help: "Leave blank for the usual 6379."),
                F("tls", "Use TLS", FieldKind.Bool, @default: "true"),
                Username(placeholder: "Leave empty for the default user", required: false),
                Password(required: false),
            ],
            Outputs =
            [
                O(OutputKeys.ConnectionString, "Connection URL", "uri", ("scheme", "redis"), ("tlsScheme", "rediss"), ("tlsField", "tls"), ("port", "port"),
                  ("user", "username"), ("password", "password")),
            ],
            Tester = "tcp",
        },
        new()
        {
            Key = "RabbitMqConnection", Title = "RabbitMQ broker", Category = Categories.Messaging, Icon = "layers", Color = "#ff6600",
            Description = "Address, virtual host and login for a RabbitMQ (AMQP) broker.",
            Fields =
            [
                F("host", "Server name", FieldKind.Host, required: true, placeholder: "e.g. mq-prod.corp.local"),
                F("port", "Port", FieldKind.Port, placeholder: "5672", help: "Leave blank for the usual 5672 (5671 with TLS)."),
                F("virtualHost", "Virtual host", @default: "/"),
                F("tls", "Use TLS", FieldKind.Bool, @default: "true"),
                Username(),
                Password(),
            ],
            Outputs =
            [
                O(OutputKeys.ConnectionString, "Connection URL", "uri", ("scheme", "amqp"), ("tlsScheme", "amqps"), ("tlsField", "tls"), ("port", "port"),
                  ("path", "virtualHost"), ("user", "username"), ("password", "password")),
            ],
            Tester = "tcp",
        },
        new()
        {
            Key = "KafkaSasl", Title = "Kafka (SASL login)", Category = Categories.Messaging, Icon = "activity", Color = "#94a3b8",
            Description = "Bootstrap servers and SASL credentials for an Apache Kafka cluster.",
            Fields =
            [
                F("bootstrapServers", "Bootstrap servers", required: true, placeholder: "e.g. kafka-1:9093,kafka-2:9093"),
                F("securityProtocol", "Security protocol", FieldKind.Select, @default: "SASL_SSL", options: ["SASL_SSL", "SASL_PLAINTEXT"]),
                F("saslMechanism", "SASL mechanism", FieldKind.Select, @default: "SCRAM-SHA-512", options: ["SCRAM-SHA-512", "SCRAM-SHA-256", "PLAIN"]),
                F("loginModule", "JAAS login module", FieldKind.Select, advanced: true, @default: "org.apache.kafka.common.security.scram.ScramLoginModule",
                  options: ["org.apache.kafka.common.security.scram.ScramLoginModule", "org.apache.kafka.common.security.plain.PlainLoginModule"],
                  help: "Use PlainLoginModule with the PLAIN mechanism."),
                Username(),
                Password(),
            ],
            Outputs =
            [
                O("properties", "Client properties", "template", ("template",
                    "bootstrap.servers={{bootstrapServers}}\nsecurity.protocol={{securityProtocol}}\nsasl.mechanism={{saslMechanism}}\n" +
                    "sasl.jaas.config={{loginModule}} required username=\"{{username|quoted}}\" password=\"{{password|quoted}}\";\n")),
            ],
        },

        // ===================== logins =====================
        new()
        {
            Key = "OAuthClient", Title = "OAuth client (client credentials)", Category = Categories.Login, Icon = "link", Color = "#0ea5e9",
            Description = "Client ID and secret an application uses to get access tokens from an identity provider.",
            Fields =
            [
                F("tokenUrl", "Token URL", FieldKind.Url, required: true, placeholder: "e.g. https://login.example.com/oauth2/token"),
                F("clientId", "Client ID", required: true),
                F("clientSecret", "Client secret", FieldKind.Password, sensitive: true, required: true),
                F("scope", "Scope", placeholder: "e.g. api://billing/.default"),
                F("audience", "Audience", advanced: true),
            ],
        },
        new()
        {
            Key = "LdapBind", Title = "LDAP / Active Directory bind", Category = Categories.Login, Icon = "users", Color = "#6366f1",
            Description = "Account an application uses to look up users and groups in a directory.",
            Fields =
            [
                F("url", "Directory address", FieldKind.Url, required: true, placeholder: "e.g. ldaps://dc01.corp.local:636"),
                F("bindDn", "Bind DN", required: true, placeholder: "e.g. CN=svc_ldap,OU=Service Accounts,DC=corp,DC=local"),
                F("password", "Password", FieldKind.Password, sensitive: true, required: true),
                F("baseDn", "Search base", placeholder: "e.g. DC=corp,DC=local"),
            ],
            Tester = "tcp",
        },
        new()
        {
            Key = "SftpLogin", Title = "SFTP login", Category = Categories.Login, Icon = "server", Color = "#0d9488",
            Description = "Server and login for an SFTP file transfer, with a password or a private key.",
            Fields =
            [
                F("host", "Server name", FieldKind.Host, required: true, placeholder: "e.g. sftp.partner.example"),
                F("port", "Port", FieldKind.Port, placeholder: "22"),
                Username(placeholder: "e.g. nimbus_upload"),
                F("password", "Password", FieldKind.Password, sensitive: true),
                F("privateKey", "Private key", FieldKind.Pem, sensitive: true, help: "Instead of a password: an OpenSSH or PEM private key."),
            ],
            RequireOneOf = [["password", "privateKey"]],
            Outputs = [O("url", "Address", "uri", ("scheme", "sftp"), ("port", "port"), ("user", "username"))],
            Tester = "tcp",
        },

        // ===================== keys and certificates =====================
        new()
        {
            Key = "SshKey", Title = "SSH key", Category = Categories.Key, Icon = "code", Color = "#475569",
            Description = "A private key (and optional passphrase) for SSH access to a server.",
            Fields =
            [
                F("host", "Server name", FieldKind.Host, placeholder: "e.g. bastion.corp.local"),
                F("port", "Port", FieldKind.Port, placeholder: "22"),
                Username(placeholder: "e.g. deploy", required: false),
                F("privateKey", "Private key", FieldKind.Pem, sensitive: true, required: true, help: "Paste the whole key, including the BEGIN and END lines."),
                F("passphrase", "Passphrase", FieldKind.Password, sensitive: true),
                F("publicKey", "Public key", FieldKind.Multiline, help: "Safe to share; handy for adding to authorized_keys."),
            ],
            Tester = "tcp",
        },
        new()
        {
            Key = "TlsCertificate", Title = "TLS certificate", Category = Categories.Certificate, Icon = "award", Color = "#f59e0b",
            Description = "A certificate with its private key (and optional chain), checked to make sure they match.",
            Fields =
            [
                F("certificate", "Certificate", FieldKind.Pem, required: true, help: "PEM, starting with -----BEGIN CERTIFICATE-----."),
                F("chain", "Intermediate certificates", FieldKind.Pem, help: "Optional chain, in order."),
                F("privateKey", "Private key", FieldKind.Pem, sensitive: true, required: true),
            ],
            Outputs =
            [
                O("pem", "Certificate, chain and key (PEM)", "pem-bundle", ("fields", "certificate,chain,privateKey"), ("certificateField", "certificate"), ("keyField", "privateKey")),
                O("fullchain", "Certificate and chain (PEM)", "pem-bundle", ("fields", "certificate,chain")),
            ],
        },

        // ===================== cloud =====================
        new()
        {
            Key = "AwsAccessKey", Title = "AWS access key", Category = Categories.Cloud, Icon = "server", Color = "#ff9900",
            Description = "Access key ID and secret for an AWS IAM user.",
            Fields =
            [
                F("accessKeyId", "Access key ID", required: true, pattern: "^(AKIA|ASIA)[A-Z0-9]{16}$", placeholder: "AKIA…"),
                F("secretAccessKey", "Secret access key", FieldKind.Password, sensitive: true, required: true),
                F("region", "Region", @default: "us-east-1"),
            ],
            Outputs =
            [
                O("credentialsFile", "AWS credentials file", "template", ("template",
                    "[default]\naws_access_key_id = {{accessKeyId}}\naws_secret_access_key = {{secretAccessKey}}\nregion = {{region}}\n")),
            ],
        },
        new()
        {
            Key = "AzureServicePrincipal", Title = "Azure service principal", Category = Categories.Cloud, Icon = "globe", Color = "#0078d4",
            Description = "Tenant, client ID and secret for an Entra ID app registration.",
            Fields =
            [
                F("tenantId", "Tenant ID", required: true),
                F("clientId", "Client (application) ID", required: true),
                F("clientSecret", "Client secret", FieldKind.Password, sensitive: true, required: true),
                F("subscriptionId", "Subscription ID"),
            ],
            Outputs =
            [
                O("env", "Environment variables", "template", ("template",
                    "AZURE_TENANT_ID={{tenantId}}\nAZURE_CLIENT_ID={{clientId}}\nAZURE_CLIENT_SECRET={{clientSecret}}\nAZURE_SUBSCRIPTION_ID={{subscriptionId}}\n")),
            ],
        },
    ];
}

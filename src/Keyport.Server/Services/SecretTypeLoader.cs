using System.Text.Json;
using System.Text.Json.Serialization;
using Keyport.Core.Secrets.Types;
using Keyport.Server.Configuration;

namespace Keyport.Server.Services;

/// <summary>
/// Builds the secret-type registry from the built-in catalog, the <c>Keyport:SecretTypes</c> configuration section,
/// and <c>*.json</c> files in <c>{DataPath}/secret-types</c> (one type per file, or an array of types).
/// </summary>
public static class SecretTypeLoader
{
    public const string FolderName = "secret-types";

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    {
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static SecretTypeRegistry Load(KeyportOptions options)
    {
        var definitions = new List<SecretTypeDefinition>(BuiltInTypes.All);

        foreach (var d in options.SecretTypes)
        {
            d.Source = "configuration";
            definitions.Add(d);
        }

        var folder = Path.Combine(options.DataPath, FolderName);
        if (Directory.Exists(folder))
        {
            foreach (var file in Directory.GetFiles(folder, "*.json").Order(StringComparer.Ordinal))
            {
                List<SecretTypeDefinition> fromFile;
                try
                {
                    var text = File.ReadAllText(file);
                    fromFile = text.TrimStart().StartsWith('[')
                        ? JsonSerializer.Deserialize<List<SecretTypeDefinition>>(text, Json) ?? []
                        : [JsonSerializer.Deserialize<SecretTypeDefinition>(text, Json) ?? throw new JsonException("empty file")];
                }
                catch (JsonException e)
                {
                    throw new SecretTypeDefinitionException($"Secret type file '{Path.GetFileName(file)}' is not valid JSON: {e.Message}");
                }
                foreach (var d in fromFile)
                {
                    d.Source = $"file: {Path.GetFileName(file)}";
                    definitions.Add(d);
                }
            }
        }

        return SecretTypeRegistry.Create(definitions);
    }
}

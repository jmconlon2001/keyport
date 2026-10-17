using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.XmlEncryption;
using SecretManager.Core.Crypto;

namespace SecretManager.Server.Edge;

/// <summary>
/// Encrypts ASP.NET Core data-protection keys (which protect auth cookies and antiforgery tokens) at rest
/// with the master key, so a copy of the data volume alone cannot forge sessions.
/// </summary>
public sealed class KekXmlEncryptor(EnvelopeEncryptor encryptor) : IXmlEncryptor
{
    internal const string Aad = "dataprotection|key";

    public EncryptedXmlInfo Encrypt(XElement plaintextElement)
    {
        var blob = encryptor.EncryptString(plaintextElement.ToString(SaveOptions.DisableFormatting), Aad);
        var element = new XElement("kekEncrypted",
            new XAttribute("keyId", blob.KeyId),
            new XElement("dek", Convert.ToBase64String(blob.WrappedDek)),
            new XElement("value", Convert.ToBase64String(blob.Ciphertext)));
        return new EncryptedXmlInfo(element, typeof(KekXmlDecryptor));
    }
}

public sealed class KekXmlDecryptor(IServiceProvider services) : IXmlDecryptor
{
    public XElement Decrypt(XElement encryptedElement)
    {
        var encryptor = services.GetRequiredService<EnvelopeEncryptor>();
        var blob = new EncryptedBlob(
            Convert.FromBase64String(encryptedElement.Element("dek")!.Value),
            Convert.FromBase64String(encryptedElement.Element("value")!.Value),
            encryptedElement.Attribute("keyId")!.Value);
        return XElement.Parse(encryptor.DecryptString(blob, KekXmlEncryptor.Aad));
    }
}

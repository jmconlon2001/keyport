using System.Security.Cryptography;
using System.Text;

namespace Keyport.Core.Crypto;

/// <summary>Result of envelope encryption. All fields are safe to store; none is usable without the KEK.</summary>
/// <param name="WrappedDek">nonce(12) || AES-GCM(KEK, DEK) || tag(16)</param>
/// <param name="Ciphertext">nonce(12) || AES-GCM(DEK, plaintext) || tag(16)</param>
/// <param name="KeyId">Identifier of the KEK that wrapped the DEK.</param>
public sealed record EncryptedBlob(byte[] WrappedDek, byte[] Ciphertext, string KeyId);

/// <summary>
/// Envelope encryption: every value gets a fresh random 256-bit DEK; the DEK is wrapped by the KEK.
/// Both layers use AES-256-GCM and bind the caller-supplied associated data (AAD), so a blob
/// copied to another record/environment fails authentication.
/// </summary>
public sealed class EnvelopeEncryptor(MasterKey kek)
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private static readonly byte[] WrapContext = "sm-dek-wrap-v1|"u8.ToArray();

    public string KeyId => kek.KeyId;

    public EncryptedBlob Encrypt(ReadOnlySpan<byte> plaintext, string aad)
    {
        var dek = RandomNumberGenerator.GetBytes(32);
        try
        {
            var aadBytes = Encoding.UTF8.GetBytes(aad);
            var ciphertext = Seal(dek, plaintext, aadBytes);
            var wrapped = Seal(kek.Bytes, dek, WrapAad(aadBytes));
            return new EncryptedBlob(wrapped, ciphertext, kek.KeyId);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public EncryptedBlob EncryptString(string plaintext, string aad) => Encrypt(Encoding.UTF8.GetBytes(plaintext), aad);

    /// <exception cref="CryptographicException">Tampered data, wrong AAD, or wrong KEK.</exception>
    public byte[] Decrypt(EncryptedBlob blob, string aad)
    {
        var aadBytes = Encoding.UTF8.GetBytes(aad);
        var dek = Open(kek.Bytes, blob.WrappedDek, WrapAad(aadBytes));
        try
        {
            return Open(dek, blob.Ciphertext, aadBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    public string DecryptString(EncryptedBlob blob, string aad) => Encoding.UTF8.GetString(Decrypt(blob, aad));

    /// <summary>Re-wraps the DEK under <paramref name="newKek"/> without touching the ciphertext (KEK rotation).</summary>
    public EncryptedBlob Rewrap(EncryptedBlob blob, string aad, MasterKey newKek)
    {
        var wrapAad = WrapAad(Encoding.UTF8.GetBytes(aad));
        var dek = Open(kek.Bytes, blob.WrappedDek, wrapAad);
        try
        {
            return blob with { WrappedDek = Seal(newKek.Bytes, dek, wrapAad), KeyId = newKek.KeyId };
        }
        finally
        {
            CryptographicOperations.ZeroMemory(dek);
        }
    }

    private static byte[] WrapAad(byte[] aad)
    {
        var r = new byte[WrapContext.Length + aad.Length];
        WrapContext.CopyTo(r, 0);
        aad.CopyTo(r, WrapContext.Length);
        return r;
    }

    private static byte[] Seal(ReadOnlySpan<byte> key, ReadOnlySpan<byte> plaintext, ReadOnlySpan<byte> aad)
    {
        var output = new byte[NonceSize + plaintext.Length + TagSize];
        var nonce = output.AsSpan(0, NonceSize);
        RandomNumberGenerator.Fill(nonce);
        using var gcm = new AesGcm(key, TagSize);
        gcm.Encrypt(nonce, plaintext, output.AsSpan(NonceSize, plaintext.Length), output.AsSpan(NonceSize + plaintext.Length), aad);
        return output;
    }

    private static byte[] Open(ReadOnlySpan<byte> key, ReadOnlySpan<byte> sealedData, ReadOnlySpan<byte> aad)
    {
        if (sealedData.Length < NonceSize + TagSize)
            throw new CryptographicException("Ciphertext is too short.");
        var ctLength = sealedData.Length - NonceSize - TagSize;
        var plaintext = new byte[ctLength];
        using var gcm = new AesGcm(key, TagSize);
        gcm.Decrypt(sealedData[..NonceSize], sealedData.Slice(NonceSize, ctLength), sealedData[(NonceSize + ctLength)..], plaintext, aad);
        return plaintext;
    }
}

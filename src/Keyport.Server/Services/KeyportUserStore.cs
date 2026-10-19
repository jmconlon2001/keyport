using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Keyport.Core.Crypto;
using Keyport.Server.Data;

namespace Keyport.Server.Services;

/// <summary>
/// Identity's user store, with every user token (authenticator app keys and recovery codes) encrypted at rest under
/// the master key, like secrets. A database copy alone can't be used to clone someone's authenticator.
/// </summary>
public sealed class KeyportUserStore(ApplicationDbContext context, EnvelopeEncryptor encryptor, IdentityErrorDescriber? describer = null)
    : UserStore<ApplicationUser, IdentityRole, ApplicationDbContext, string, IdentityUserClaim<string>, IdentityUserRole<string>,
        IdentityUserLogin<string>, IdentityUserToken<string>, IdentityRoleClaim<string>, IdentityUserPasskey<string>>(context, describer)
{
    public override Task SetTokenAsync(ApplicationUser user, string loginProvider, string name, string? value, CancellationToken cancellationToken = default) =>
        base.SetTokenAsync(user, loginProvider, name, value is null ? null : ProtectedTokens.Protect(encryptor, user.Id, loginProvider, name, value), cancellationToken);

    public override async Task<string?> GetTokenAsync(ApplicationUser user, string loginProvider, string name, CancellationToken cancellationToken = default)
    {
        var stored = await base.GetTokenAsync(user, loginProvider, name, cancellationToken);
        return stored is null ? null : ProtectedTokens.Unprotect(encryptor, user.Id, loginProvider, name, stored);
    }
}

/// <summary>Encryption format for Identity user tokens: <c>kp-enc:v1:{keyId}:{wrappedDek}:{ciphertext}</c> (base64), bound to user and token name.</summary>
public static class ProtectedTokens
{
    private const string Prefix = "kp-enc:v1:";

    private static string Aad(string userId, string provider, string name) => $"identity-token|{userId}|{provider}|{name}";

    public static bool IsProtected(string? value) => value?.StartsWith(Prefix, StringComparison.Ordinal) == true;

    public static string Protect(EnvelopeEncryptor e, string userId, string provider, string name, string value) =>
        Format(e.EncryptString(value, Aad(userId, provider, name)));

    /// <summary>Decrypts; values written before encryption was added are returned as they are (and encrypted at the next start).</summary>
    public static string Unprotect(EnvelopeEncryptor e, string userId, string provider, string name, string stored) =>
        IsProtected(stored) ? e.DecryptString(Parse(stored), Aad(userId, provider, name)) : stored;

    /// <summary>Encrypts any token still stored in clear. Run at startup.</summary>
    public static async Task<int> EncryptExistingAsync(ApplicationDbContext db, EnvelopeEncryptor e)
    {
        var clear = (await db.UserTokens.ToListAsync()).Where(t => t.Value is not null && !IsProtected(t.Value)).ToList();
        foreach (var t in clear) t.Value = Protect(e, t.UserId, t.LoginProvider, t.Name, t.Value!);
        await db.SaveChangesAsync();
        return clear.Count;
    }

    /// <summary>Re-wraps every token under a new master key (KEK rotation).</summary>
    public static async Task<int> RewrapAllAsync(ApplicationDbContext db, EnvelopeEncryptor current, MasterKey newKek)
    {
        var tokens = (await db.UserTokens.ToListAsync()).Where(t => IsProtected(t.Value)).ToList();
        foreach (var t in tokens)
            t.Value = Format(current.Rewrap(Parse(t.Value!), Aad(t.UserId, t.LoginProvider, t.Name), newKek));
        await db.SaveChangesAsync();
        return tokens.Count;
    }

    private static string Format(EncryptedBlob b) =>
        $"{Prefix}{b.KeyId}:{Convert.ToBase64String(b.WrappedDek)}:{Convert.ToBase64String(b.Ciphertext)}";

    private static EncryptedBlob Parse(string stored)
    {
        var parts = stored[Prefix.Length..].Split(':');
        if (parts.Length != 3) throw new FormatException("Malformed protected token.");
        return new EncryptedBlob(Convert.FromBase64String(parts[1]), Convert.FromBase64String(parts[2]), parts[0]);
    }
}

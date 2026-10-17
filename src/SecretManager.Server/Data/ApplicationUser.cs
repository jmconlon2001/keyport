using Microsoft.AspNetCore.Identity;

namespace SecretManager.Server.Data;

public class ApplicationUser : IdentityUser
{
    public string? DisplayName { get; set; }

    /// <summary>Set for new accounts and admin password resets; the user must choose a new password before doing anything else.</summary>
    public bool MustChangePassword { get; set; }

    public DateTime CreatedUtc { get; set; }
}

public static class Roles
{
    /// <summary>Full access to every environment, users, clients and certificates.</summary>
    public const string Admin = "Admin";

    /// <summary>Read-only access to the audit log.</summary>
    public const string Auditor = "Auditor";

    public static readonly string[] All = [Admin, Auditor];
}

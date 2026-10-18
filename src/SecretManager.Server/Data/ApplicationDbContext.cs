using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace SecretManager.Server.Data;

public class ApplicationDbContext(DbContextOptions<ApplicationDbContext> options) : IdentityDbContext<ApplicationUser>(options)
{
    public DbSet<EnvironmentDef> Environments => Set<EnvironmentDef>();
    public DbSet<Secret> Secrets => Set<Secret>();
    public DbSet<SecretVersion> SecretVersions => Set<SecretVersion>();
    public DbSet<ApiClient> ApiClients => Set<ApiClient>();
    public DbSet<ApiClientGrant> ApiClientGrants => Set<ApiClientGrant>();
    public DbSet<UserEnvironmentRole> UserEnvironmentRoles => Set<UserEnvironmentRole>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<AppSetting> AppSettings => Set<AppSetting>();
    public DbSet<ActivityLog> ActivityLogs => Set<ActivityLog>();
    public DbSet<ProxyRoute> ProxyRoutes => Set<ProxyRoute>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);

        b.Entity<EnvironmentDef>(e =>
        {
            e.HasIndex(x => x.Name).IsUnique();
            e.Property(x => x.Name).HasMaxLength(50);
        });

        b.Entity<Secret>(e =>
        {
            e.HasIndex(x => new { x.EnvironmentId, x.Name }).IsUnique();
            e.Property(x => x.Name).HasMaxLength(200);
            e.Property(x => x.Type).HasConversion<string>().HasMaxLength(40);
            e.HasMany(x => x.Versions).WithOne(v => v.Secret).HasForeignKey(v => v.SecretId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Environment).WithMany().OnDelete(DeleteBehavior.Restrict);
            e.Ignore(x => x.Metadata);
        });

        b.Entity<SecretVersion>(e => e.HasIndex(x => new { x.SecretId, x.Version }).IsUnique());

        b.Entity<ApiClient>(e =>
        {
            e.HasIndex(x => x.KeyPrefix).IsUnique();
            e.HasIndex(x => new { x.EnvironmentId, x.Name }).IsUnique();
            e.HasMany(x => x.Grants).WithOne(g => g.ApiClient).HasForeignKey(g => g.ApiClientId).OnDelete(DeleteBehavior.Cascade);
            e.HasOne(x => x.Environment).WithMany().OnDelete(DeleteBehavior.Restrict);
        });

        b.Entity<UserEnvironmentRole>(e =>
        {
            e.HasIndex(x => new { x.UserId, x.EnvironmentId }).IsUnique();
            e.Property(x => x.Role).HasConversion<string>().HasMaxLength(20);
            e.HasOne<ApplicationUser>().WithMany().HasForeignKey(x => x.UserId).OnDelete(DeleteBehavior.Cascade);
        });

        b.Entity<AuditEvent>(e =>
        {
            // Ids are assigned by AuditService so they can be part of the hash.
            e.Property(x => x.Id).ValueGeneratedNever();
            e.HasIndex(x => x.TimestampUtc);
            e.HasIndex(x => x.Actor);
        });

        b.Entity<AppSetting>(e => e.HasKey(x => x.Key));

        b.Entity<ProxyRoute>(e =>
        {
            e.HasIndex(x => x.Name).IsUnique();
            e.HasIndex(x => x.PathPrefix).IsUnique();
            e.Property(x => x.Name).HasMaxLength(50);
            e.Property(x => x.PathPrefix).HasMaxLength(100);
            e.Property(x => x.Access).HasConversion<string>().HasMaxLength(20);
            e.Ignore(x => x.DestinationList);
            e.Ignore(x => x.PortList);
        });

        b.Entity<ActivityLog>(e =>
        {
            e.HasIndex(x => new { x.Source, x.TimestampUtc });
            e.HasIndex(x => x.Environment);
            e.HasIndex(x => x.Actor);
        });
    }
}

/// <summary>Lets `dotnet ef` create migrations without running the app's startup (which needs the master key).</summary>
public class DesignTimeDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext>
{
    public ApplicationDbContext CreateDbContext(string[] args)
    {
        // Identity reads its schema version (v3 = passkeys) from the application's IdentityOptions.
        var services = new ServiceCollection()
            .Configure<Microsoft.AspNetCore.Identity.IdentityOptions>(o => o.Stores.SchemaVersion = Microsoft.AspNetCore.Identity.IdentitySchemaVersions.Version3)
            .BuildServiceProvider();
        return new(new DbContextOptionsBuilder<ApplicationDbContext>()
            .UseSqlite("Data Source=design-time.db")
            .UseApplicationServiceProvider(services)
            .Options);
    }
}

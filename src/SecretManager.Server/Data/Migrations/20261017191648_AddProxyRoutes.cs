using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretManager.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddProxyRoutes : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ProxyRoutes",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    Name = table.Column<string>(type: "TEXT", maxLength: 50, nullable: false),
                    Description = table.Column<string>(type: "TEXT", nullable: true),
                    PathPrefix = table.Column<string>(type: "TEXT", maxLength: 100, nullable: false),
                    Destinations = table.Column<string>(type: "TEXT", nullable: false),
                    Ports = table.Column<string>(type: "TEXT", nullable: false),
                    Access = table.Column<string>(type: "TEXT", maxLength: 20, nullable: false),
                    StripPrefix = table.Column<bool>(type: "INTEGER", nullable: false),
                    RelaxCsp = table.Column<bool>(type: "INTEGER", nullable: false),
                    LoadBalancing = table.Column<string>(type: "TEXT", nullable: false),
                    HealthCheckPath = table.Column<string>(type: "TEXT", nullable: true),
                    Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    CreatedBy = table.Column<string>(type: "TEXT", nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UpdatedBy = table.Column<string>(type: "TEXT", nullable: false),
                    UpdatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProxyRoutes", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ProxyRoutes_Name",
                table: "ProxyRoutes",
                column: "Name",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ProxyRoutes_PathPrefix",
                table: "ProxyRoutes",
                column: "PathPrefix",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ProxyRoutes");
        }
    }
}

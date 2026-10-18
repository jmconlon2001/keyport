using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace SecretManager.Server.Data.Migrations
{
    /// <inheritdoc />
    public partial class AddApiKeyCreatedUtc : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTime>(
                name: "KeyCreatedUtc",
                table: "ApiClients",
                type: "TEXT",
                nullable: false,
                defaultValue: new DateTime(1, 1, 1, 0, 0, 0, 0, DateTimeKind.Unspecified));

            // Existing clients: key history wasn't tracked before, so the creation date is the best known issue date.
            migrationBuilder.Sql("UPDATE ApiClients SET KeyCreatedUtc = CreatedUtc;");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "KeyCreatedUtc",
                table: "ApiClients");
        }
    }
}

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Messenger.Data.Migrations
{
    /// <inheritdoc />
    public partial class Licensing : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "licenses",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    raw_document = table.Column<string>(type: "text", nullable: false),
                    license_id = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    customer = table.Column<string>(type: "text", nullable: false),
                    not_before = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    not_after = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    is_active = table.Column<bool>(type: "boolean", nullable: false),
                    installed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    installed_by = table.Column<Guid>(type: "uuid", nullable: true),
                    activated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_heartbeat_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_licenses", x => x.id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_licenses_is_active",
                table: "licenses",
                column: "is_active");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "licenses");
        }
    }
}

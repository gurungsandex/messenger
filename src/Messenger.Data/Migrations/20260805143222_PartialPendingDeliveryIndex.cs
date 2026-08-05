using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Messenger.Data.Migrations
{
    /// <inheritdoc />
    public partial class PartialPendingDeliveryIndex : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_message_recipients_user_id_state",
                table: "message_recipients");

            migrationBuilder.CreateIndex(
                name: "IX_message_recipients_user_id_state",
                table: "message_recipients",
                columns: new[] { "user_id", "state" },
                filter: "state = 0");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_message_recipients_user_id_state",
                table: "message_recipients");

            migrationBuilder.CreateIndex(
                name: "IX_message_recipients_user_id_state",
                table: "message_recipients",
                columns: new[] { "user_id", "state" });
        }
    }
}

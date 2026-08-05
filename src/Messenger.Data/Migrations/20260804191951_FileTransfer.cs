using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Messenger.Data.Migrations
{
    /// <inheritdoc />
    public partial class FileTransfer : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "files",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    conversation_id = table.Column<Guid>(type: "uuid", nullable: false),
                    message_id = table.Column<Guid>(type: "uuid", nullable: true),
                    uploader_id = table.Column<Guid>(type: "uuid", nullable: false),
                    file_name = table.Column<string>(type: "character varying(255)", maxLength: 255, nullable: false),
                    content_type = table.Column<string>(type: "text", nullable: true),
                    size_bytes = table.Column<long>(type: "bigint", nullable: false),
                    sha256_plaintext = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    storage_key = table.Column<string>(type: "character varying(64)", maxLength: 64, nullable: false),
                    wrapped_dek = table.Column<byte[]>(type: "bytea", nullable: false),
                    kek_id = table.Column<string>(type: "text", nullable: false),
                    key_version = table.Column<int>(type: "integer", nullable: false),
                    nonce_prefix = table.Column<byte[]>(type: "bytea", maxLength: 4, nullable: false),
                    chunk_size = table.Column<int>(type: "integer", nullable: false),
                    chunk_count = table.Column<long>(type: "bigint", nullable: false),
                    chunk_manifest = table.Column<byte[]>(type: "bytea", nullable: true),
                    upload_state = table.Column<int>(type: "integer", nullable: false),
                    av_state = table.Column<int>(type: "integer", nullable: false),
                    av_detail = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    completed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    deleted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_files", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "file_chunks",
                columns: table => new
                {
                    file_id = table.Column<Guid>(type: "uuid", nullable: false),
                    chunk_index = table.Column<long>(type: "bigint", nullable: false),
                    byte_length = table.Column<int>(type: "integer", nullable: false),
                    auth_tag = table.Column<byte[]>(type: "bytea", maxLength: 16, nullable: false),
                    received_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_file_chunks", x => new { x.file_id, x.chunk_index });
                    table.ForeignKey(
                        name: "FK_file_chunks_files_file_id",
                        column: x => x.file_id,
                        principalTable: "files",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_files_conversation_id",
                table: "files",
                column: "conversation_id");

            migrationBuilder.CreateIndex(
                name: "IX_files_storage_key",
                table: "files",
                column: "storage_key",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_files_upload_state",
                table: "files",
                column: "upload_state");

            migrationBuilder.CreateIndex(
                name: "IX_files_uploader_id_deleted_at",
                table: "files",
                columns: new[] { "uploader_id", "deleted_at" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "file_chunks");

            migrationBuilder.DropTable(
                name: "files");
        }
    }
}

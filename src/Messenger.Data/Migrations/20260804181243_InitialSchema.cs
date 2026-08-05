using System;
using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace Messenger.Data.Migrations
{
    /// <inheritdoc />
    public partial class InitialSchema : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "audit_checkpoints",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    up_to_audit_id = table.Column<long>(type: "bigint", nullable: false),
                    head_hash = table.Column<byte[]>(type: "bytea", nullable: false),
                    signature = table.Column<byte[]>(type: "bytea", nullable: false),
                    signing_key_id = table.Column<string>(type: "text", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    anchored_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    anchor_reference = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_checkpoints", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "audit_log",
                columns: table => new
                {
                    id = table.Column<long>(type: "bigint", nullable: false)
                        .Annotation("Npgsql:ValueGenerationStrategy", NpgsqlValueGenerationStrategy.IdentityByDefaultColumn),
                    occurred_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    actor_user_id = table.Column<Guid>(type: "uuid", nullable: true),
                    actor_tier = table.Column<string>(type: "text", nullable: false),
                    actor_ip = table.Column<string>(type: "text", nullable: true),
                    action = table.Column<string>(type: "character varying(128)", maxLength: 128, nullable: false),
                    target_type = table.Column<string>(type: "text", nullable: true),
                    target_id = table.Column<Guid>(type: "uuid", nullable: true),
                    outcome = table.Column<string>(type: "text", nullable: false),
                    detail_json = table.Column<string>(type: "text", nullable: true),
                    prev_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    entry_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_audit_log", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "conversations",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    type = table.Column<int>(type: "integer", nullable: false),
                    direct_key = table.Column<string>(type: "text", nullable: true),
                    title = table.Column<string>(type: "text", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    created_by = table.Column<Guid>(type: "uuid", nullable: true),
                    last_message_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    next_seq = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_conversations", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "presence",
                columns: table => new
                {
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    status = table.Column<int>(type: "integer", nullable: false),
                    status_message = table.Column<string>(type: "text", nullable: true),
                    is_auto_away = table.Column<bool>(type: "boolean", nullable: false),
                    changed_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_presence", x => x.user_id);
                });

            migrationBuilder.CreateTable(
                name: "server_settings",
                columns: table => new
                {
                    key = table.Column<string>(type: "text", nullable: false),
                    value = table.Column<string>(type: "text", nullable: false),
                    is_secret = table.Column<bool>(type: "boolean", nullable: false),
                    updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_server_settings", x => x.key);
                });

            migrationBuilder.CreateTable(
                name: "users",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    username = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    source = table.Column<int>(type: "integer", nullable: false),
                    ad_object_guid = table.Column<Guid>(type: "uuid", nullable: true),
                    ad_dn = table.Column<string>(type: "text", nullable: true),
                    display_name = table.Column<string>(type: "character varying(256)", maxLength: 256, nullable: false),
                    email = table.Column<string>(type: "text", nullable: true),
                    password_hash = table.Column<string>(type: "text", nullable: true),
                    password_updated_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    must_change_password = table.Column<bool>(type: "boolean", nullable: false),
                    status = table.Column<int>(type: "integer", nullable: false),
                    failed_login_count = table.Column<int>(type: "integer", nullable: false),
                    lockout_until = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_login_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    deleted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_users", x => x.id);
                });

            migrationBuilder.CreateTable(
                name: "conversation_keys",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    conversation_id = table.Column<Guid>(type: "uuid", nullable: false),
                    version = table.Column<int>(type: "integer", nullable: false),
                    wrapped_dek = table.Column<byte[]>(type: "bytea", nullable: false),
                    kek_id = table.Column<string>(type: "text", nullable: false),
                    algorithm = table.Column<string>(type: "text", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    retired_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    message_count = table.Column<long>(type: "bigint", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_conversation_keys", x => x.id);
                    table.ForeignKey(
                        name: "FK_conversation_keys_conversations_conversation_id",
                        column: x => x.conversation_id,
                        principalTable: "conversations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "messages",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    conversation_id = table.Column<Guid>(type: "uuid", nullable: false),
                    seq = table.Column<long>(type: "bigint", nullable: false),
                    sender_id = table.Column<Guid>(type: "uuid", nullable: false),
                    client_message_id = table.Column<Guid>(type: "uuid", nullable: false),
                    ciphertext = table.Column<byte[]>(type: "bytea", nullable: false),
                    nonce = table.Column<byte[]>(type: "bytea", maxLength: 12, nullable: false),
                    auth_tag = table.Column<byte[]>(type: "bytea", maxLength: 16, nullable: false),
                    key_id = table.Column<Guid>(type: "uuid", nullable: false),
                    aad_version = table.Column<short>(type: "smallint", nullable: false),
                    sent_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    server_received_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    edited_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    deleted_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_messages", x => x.id);
                    table.ForeignKey(
                        name: "FK_messages_conversations_conversation_id",
                        column: x => x.conversation_id,
                        principalTable: "conversations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "conversation_participants",
                columns: table => new
                {
                    conversation_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    joined_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    left_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    last_read_seq = table.Column<long>(type: "bigint", nullable: false),
                    is_muted = table.Column<bool>(type: "boolean", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_conversation_participants", x => new { x.conversation_id, x.user_id });
                    table.ForeignKey(
                        name: "FK_conversation_participants_conversations_conversation_id",
                        column: x => x.conversation_id,
                        principalTable: "conversations",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                    table.ForeignKey(
                        name: "FK_conversation_participants_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "sessions",
                columns: table => new
                {
                    id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    token_hash = table.Column<byte[]>(type: "bytea", maxLength: 32, nullable: false),
                    device_fingerprint = table.Column<string>(type: "text", nullable: false),
                    device_name = table.Column<string>(type: "text", nullable: true),
                    ip_address = table.Column<string>(type: "text", nullable: true),
                    auth_method = table.Column<int>(type: "integer", nullable: false),
                    created_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    last_activity_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    expires_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: false),
                    revoked_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    revoke_reason = table.Column<string>(type: "text", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_sessions", x => x.id);
                    table.ForeignKey(
                        name: "FK_sessions_users_user_id",
                        column: x => x.user_id,
                        principalTable: "users",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateTable(
                name: "message_recipients",
                columns: table => new
                {
                    message_id = table.Column<Guid>(type: "uuid", nullable: false),
                    user_id = table.Column<Guid>(type: "uuid", nullable: false),
                    state = table.Column<int>(type: "integer", nullable: false),
                    delivered_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true),
                    read_at = table.Column<DateTimeOffset>(type: "timestamp with time zone", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_message_recipients", x => new { x.message_id, x.user_id });
                    table.ForeignKey(
                        name: "FK_message_recipients_messages_message_id",
                        column: x => x.message_id,
                        principalTable: "messages",
                        principalColumn: "id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_audit_checkpoints_up_to_audit_id",
                table: "audit_checkpoints",
                column: "up_to_audit_id");

            migrationBuilder.CreateIndex(
                name: "IX_audit_log_actor_user_id",
                table: "audit_log",
                column: "actor_user_id");

            migrationBuilder.CreateIndex(
                name: "IX_audit_log_occurred_at",
                table: "audit_log",
                column: "occurred_at");

            migrationBuilder.CreateIndex(
                name: "IX_conversation_keys_conversation_id_version",
                table: "conversation_keys",
                columns: new[] { "conversation_id", "version" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_conversation_participants_user_id",
                table: "conversation_participants",
                column: "user_id");

            migrationBuilder.CreateIndex(
                name: "IX_conversations_direct_key",
                table: "conversations",
                column: "direct_key",
                unique: true,
                filter: "direct_key IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_conversations_last_message_at",
                table: "conversations",
                column: "last_message_at");

            migrationBuilder.CreateIndex(
                name: "IX_message_recipients_user_id_state",
                table: "message_recipients",
                columns: new[] { "user_id", "state" });

            migrationBuilder.CreateIndex(
                name: "IX_messages_conversation_id_sender_id_client_message_id",
                table: "messages",
                columns: new[] { "conversation_id", "sender_id", "client_message_id" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_messages_conversation_id_seq",
                table: "messages",
                columns: new[] { "conversation_id", "seq" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_messages_conversation_id_server_received_at",
                table: "messages",
                columns: new[] { "conversation_id", "server_received_at" });

            migrationBuilder.CreateIndex(
                name: "IX_sessions_token_hash",
                table: "sessions",
                column: "token_hash",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_sessions_user_id_revoked_at",
                table: "sessions",
                columns: new[] { "user_id", "revoked_at" });

            migrationBuilder.CreateIndex(
                name: "IX_users_ad_object_guid",
                table: "users",
                column: "ad_object_guid",
                unique: true,
                filter: "ad_object_guid IS NOT NULL");

            migrationBuilder.CreateIndex(
                name: "IX_users_status",
                table: "users",
                column: "status");

            migrationBuilder.CreateIndex(
                name: "IX_users_username",
                table: "users",
                column: "username",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "audit_checkpoints");

            migrationBuilder.DropTable(
                name: "audit_log");

            migrationBuilder.DropTable(
                name: "conversation_keys");

            migrationBuilder.DropTable(
                name: "conversation_participants");

            migrationBuilder.DropTable(
                name: "message_recipients");

            migrationBuilder.DropTable(
                name: "presence");

            migrationBuilder.DropTable(
                name: "server_settings");

            migrationBuilder.DropTable(
                name: "sessions");

            migrationBuilder.DropTable(
                name: "messages");

            migrationBuilder.DropTable(
                name: "users");

            migrationBuilder.DropTable(
                name: "conversations");
        }
    }
}

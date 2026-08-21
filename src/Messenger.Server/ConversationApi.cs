using Messenger.Contracts;
using Messenger.Core;
using Messenger.Data;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Server;

/// <summary>
/// Lets a logged-in user discover what they can open. <c>OpenDirectConversation</c> and
/// group membership create conversations; nothing previously listed them back, which left a
/// client with no way to populate a conversation list without already knowing every id.
/// </summary>
public static class ConversationApi
{
    public static void MapConversationApi(this WebApplication app)
    {
        var conversations = app.MapGroup("/api/conversations")
            .AddEndpointFilter<AdminAuthFilter>()
            .RequireRateLimiting("admin");

        conversations.MapGet("", async (MessageService messages, HttpContext http, CancellationToken ct) =>
            Results.Ok(await messages.GetConversationsForUserAsync(http.ActorId(), ct)));

        // A minimal, non-admin directory so a client can start a direct conversation without
        // already knowing the other user's id. Deliberately separate from GET /api/admin/users:
        // that route needs users.read and returns email/status/source, which any signed-in
        // user should not be able to enumerate. This one only needs a session, and its DTO
        // carries nothing beyond what any participant already sees on a conversation.
        app.MapGroup("/api/users")
            .AddEndpointFilter<AdminAuthFilter>()
            .RequireRateLimiting("admin")
            .MapGet("", async (string? q, MessengerDbContext db, HttpContext http, CancellationToken ct) =>
            {
                var query = db.Users.Where(u => u.DeletedAt == null
                    && u.Status == UserStatus.Active
                    && u.Id != http.ActorId());

                if (!string.IsNullOrWhiteSpace(q))
                {
                    var pattern = $"%{q.Trim()}%";
                    query = query.Where(u => EF.Functions.ILike(u.Username, pattern)
                        || EF.Functions.ILike(u.DisplayName, pattern));
                }

                var results = await query
                    .OrderBy(u => u.DisplayName)
                    .Take(50)
                    .Select(u => new UserDirectoryEntryDto(u.Id, u.Username, u.DisplayName))
                    .ToListAsync(ct);

                return Results.Ok(results);
            });
    }
}

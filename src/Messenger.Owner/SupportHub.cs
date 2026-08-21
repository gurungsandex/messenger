using Microsoft.AspNetCore.SignalR;
using Microsoft.EntityFrameworkCore;

namespace Messenger.Owner;

public sealed record SupportMessageDto(Guid Id, string CustomerLicenseId, Guid SenderId, bool SenderIsOperator, string Body, DateTimeOffset SentAt);

public interface ISupportClient
{
    Task OnSupportMessage(SupportMessageDto message);
}

/// <summary>
/// The support-chat capability (<c>vendor.support.join</c>): a small hub bridging a
/// customer's admin console to a vendor operator, one conversation per licence id. Mirrors
/// the customer server's <c>ChatHub</c> auth-by-header pattern (re-validate on connect, own
/// group membership by connection) but at a scale of a handful of concurrent conversations
/// rather than an organisation's whole chat traffic, so there is no store-and-forward
/// backlog here -- a customer reopening the console after a gap just sees history via
/// <see cref="OwnerApi"/>'s conversation read, not a replayed queue.
/// </summary>
public sealed class SupportHub(OwnerDbContext db, OwnerAuthService auth) : Hub<ISupportClient>
{
    public override async Task OnConnectedAsync()
    {
        var http = Context.GetHttpContext();
        var token = http?.Request.Headers["X-Session-Token"].FirstOrDefault()
                    ?? http?.Request.Query["access_token"].FirstOrDefault();
        var device = http?.Request.Headers["X-Device-Fingerprint"].FirstOrDefault();

        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(device))
        {
            Context.Abort();
            return;
        }

        var validation = await auth.ValidateAsync(token, device);
        if (!validation.IsValid || validation.Operator is null)
        {
            Context.Abort();
            return;
        }

        Context.Items["OperatorId"] = validation.Operator.Id;
        await base.OnConnectedAsync();
    }

    public async Task JoinSession(string customerLicenseId)
        => await Groups.AddToGroupAsync(Context.ConnectionId, GroupName(customerLicenseId));

    public async Task<SupportMessageDto> SendSupportMessage(string customerLicenseId, string body)
    {
        if (Context.Items["OperatorId"] is not Guid operatorId)
            throw new HubException("Not authenticated.");

        var message = new SupportMessage
        {
            CustomerLicenseId = customerLicenseId,
            SenderId = operatorId,
            SenderIsOperator = true,
            Body = body,
        };
        db.SupportMessages.Add(message);
        await db.SaveChangesAsync();

        var dto = new SupportMessageDto(message.Id, message.CustomerLicenseId, message.SenderId,
            message.SenderIsOperator, message.Body, message.SentAt);

        await Clients.Group(GroupName(customerLicenseId)).OnSupportMessage(dto);
        return dto;
    }

    public async Task<IReadOnlyList<SupportMessageDto>> GetHistory(string customerLicenseId, int limit = 100)
        => await db.SupportMessages
            .Where(m => m.CustomerLicenseId == customerLicenseId)
            .OrderByDescending(m => m.SentAt)
            .Take(Math.Clamp(limit, 1, 500))
            .Select(m => new SupportMessageDto(m.Id, m.CustomerLicenseId, m.SenderId, m.SenderIsOperator, m.Body, m.SentAt))
            .ToListAsync();

    private static string GroupName(string customerLicenseId) => $"support:{customerLicenseId}";
}

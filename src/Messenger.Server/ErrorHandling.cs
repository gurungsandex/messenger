using Messenger.Contracts;
using Microsoft.AspNetCore.Diagnostics;

namespace Messenger.Server;

/// <summary>
/// Maps <see cref="MessengerException"/> to a catalogue-coded HTTP response, and everything
/// else to an opaque 500 carrying only a correlation id.
///
/// Two things this prevents. Without it a service-layer failure — a permission denial, a
/// licence limit, an integrity failure — surfaces as an unhandled 500, losing the error code
/// the whole catalogue exists to provide. And an unhandled exception in a misconfigured
/// deployment can return a stack trace to the caller, disclosing internal structure.
/// </summary>
public static class ErrorHandling
{
    public static void UseMessengerErrorHandling(this WebApplication app)
    {
        app.UseExceptionHandler(builder => builder.Run(async context =>
        {
            var feature = context.Features.Get<IExceptionHandlerFeature>();
            var exception = feature?.Error;
            var logger = context.RequestServices.GetRequiredService<ILoggerFactory>()
                .CreateLogger("Messenger.ErrorHandling");

            var correlationId = context.TraceIdentifier;

            if (exception is MessengerException messengerException)
            {
                var status = StatusFor(messengerException.Code);

                // Operator detail stays in the log; the client gets the catalogue code and
                // its user-facing message only.
                logger.LogWarning("{Code} on {Path} [{CorrelationId}]: {Detail}",
                    messengerException.Code, context.Request.Path, correlationId,
                    messengerException.OperatorDetail ?? messengerException.Message);

                context.Response.StatusCode = status;
                await context.Response.WriteAsJsonAsync(
                    new ErrorDto(messengerException.Code, messengerException.Message, correlationId));
                return;
            }

            logger.LogError(exception, "Unhandled exception on {Path} [{CorrelationId}]",
                context.Request.Path, correlationId);

            context.Response.StatusCode = StatusCodes.Status500InternalServerError;
            await context.Response.WriteAsJsonAsync(new ErrorDto(
                ErrorCode.ServiceStartFailed,
                "An unexpected error occurred. Quote the correlation ID to your administrator.",
                correlationId));
        }));
    }

    private static int StatusFor(string code) => code switch
    {
        ErrorCode.PermissionDenied
            or ErrorCode.NotAConversationParticipant
            or ErrorCode.FileAccessDenied
            or ErrorCode.CrossTierEscalationRefused
            or ErrorCode.SelfModificationRefused
            or ErrorCode.LastAdminProtected
            or ErrorCode.GroupDisabled => StatusCodes.Status403Forbidden,

        ErrorCode.SessionTokenInvalid
            or ErrorCode.SessionExpiredIdle
            or ErrorCode.SessionExpiredAbsolute
            or ErrorCode.SessionRevokedByAdmin
            or ErrorCode.SessionRevokedPasswordChange
            or ErrorCode.SessionDeviceMismatch
            or ErrorCode.InvalidCredentials => StatusCodes.Status401Unauthorized,

        ErrorCode.AccountNotFound
            or ErrorCode.GroupNotFound
            or ErrorCode.FileNotFound => StatusCodes.Status404NotFound,

        ErrorCode.UserAlreadyExists
            or ErrorCode.GroupAlreadyExists => StatusCodes.Status409Conflict,

        ErrorCode.FileTooLarge => StatusCodes.Status413PayloadTooLarge,
        ErrorCode.RateLimitExceeded => StatusCodes.Status429TooManyRequests,

        ErrorCode.NoLicenseInstalled
            or ErrorCode.LicenseExpired
            or ErrorCode.GracePeriodExpired
            or ErrorCode.SeatLimitReached
            or ErrorCode.TotalSessionLimit
            or ErrorCode.PerUserSessionLimit
            or ErrorCode.FeatureNotLicensed
            or ErrorCode.LicenseNotYetValid => StatusCodes.Status403Forbidden,

        ErrorCode.DirectoryUnreachable
            or ErrorCode.DirectoryBindFailed
            or ErrorCode.SyncFailed => StatusCodes.Status502BadGateway,

        // Cryptographic and audit failures are server-side integrity problems, not client
        // errors, and must not be reported as though the caller did something wrong.
        ErrorCode.KeyStoreUnavailable
            or ErrorCode.KeyUnwrapFailed
            or ErrorCode.MessageDecryptionFailed
            or ErrorCode.FileDecryptionFailed
            or ErrorCode.ChunkManifestMismatch
            or ErrorCode.AuditWriteFailed
            or ErrorCode.AuditChainVerificationFailed => StatusCodes.Status500InternalServerError,

        _ => StatusCodes.Status400BadRequest,
    };
}

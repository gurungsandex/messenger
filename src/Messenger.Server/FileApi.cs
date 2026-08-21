using Messenger.Data;

namespace Messenger.Server;

/// <summary>
/// The wire contract for <see cref="FileTransferService"/>, which had no REST or SignalR
/// surface at all before this — every capability (chunked upload, resume, download,
/// crypto-shredding delete) already existed and was only reachable from a test host. Every
/// handler here is a thin pass-through: no policy or crypto logic lives in this file, all of
/// it is already in the service, and every <c>MessengerException</c> it throws is mapped to
/// its catalogue status code by <see cref="ErrorHandling"/>.
/// </summary>
public static class FileApi
{
    public static void MapFileApi(this WebApplication app)
    {
        var files = app.MapGroup("/api/files")
            .AddEndpointFilter<AdminAuthFilter>()
            .RequireRateLimiting("admin");

        files.MapPost("", async (
            BeginUploadRequest request, FileTransferService transfer, HttpContext http, CancellationToken ct) =>
        {
            var slot = await transfer.BeginUploadAsync(
                http.ActorId(), request.ConversationId, request.FileName, request.SizeBytes,
                Convert.FromBase64String(request.Sha256PlaintextBase64), request.ContentType, ct: ct);

            return Results.Created($"/api/files/{slot.FileId}", new
            {
                fileId = slot.FileId,
                chunkSize = slot.ChunkSize,
                chunkCount = slot.ChunkCount,
                expiresAt = slot.ExpiresAt,
            });
        });

        files.MapPut("/{id:guid}/chunks/{index:long}", async (
            Guid id, long index, HttpContext http, FileTransferService transfer, CancellationToken ct) =>
        {
            using var buffer = new MemoryStream();
            await http.Request.Body.CopyToAsync(buffer, ct);
            await transfer.UploadChunkAsync(http.ActorId(), id, index, buffer.ToArray(), ct);
            return Results.NoContent();
        });

        files.MapGet("/{id:guid}/chunks", async (
            Guid id, FileTransferService transfer, HttpContext http, CancellationToken ct) =>
            Results.Ok(await transfer.GetReceivedChunksAsync(http.ActorId(), id, ct)));

        files.MapPost("/{id:guid}/complete", async (
            Guid id, FileTransferService transfer, HttpContext http, CancellationToken ct) =>
        {
            await transfer.CompleteUploadAsync(http.ActorId(), id, ct);
            return Results.NoContent();
        });

        // Streamed rather than buffered whole: DownloadToAsync decrypts one chunk at a time,
        // so peak server memory for a download stays at one chunk regardless of file size.
        files.MapGet("/{id:guid}", async (
            Guid id, FileTransferService transfer, HttpContext http, CancellationToken ct) =>
        {
            http.Response.ContentType = "application/octet-stream";
            await transfer.DownloadToAsync(http.ActorId(), id, http.Response.Body, ct);
            return Results.Empty;
        });

        files.MapDelete("/{id:guid}", async (
            Guid id, FileTransferService transfer, HttpContext http, CancellationToken ct) =>
        {
            await transfer.DeleteAsync(http.ActorId(), id, ct: ct);
            return Results.NoContent();
        });
    }
}

public sealed record BeginUploadRequest(
    Guid ConversationId, string FileName, long SizeBytes, string Sha256PlaintextBase64, string? ContentType);

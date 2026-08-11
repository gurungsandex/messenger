# Build and run the Communication Server as a container.
#
# This is the deployment path that is actually exercised and testable today. The Windows
# Service host and MSI installer described in docs/deployment.md are still not built; this
# does not replace them, it gives the server a supported way to run in the meantime.
#
# Migrations are deliberately NOT run by this image. An unattended container restart must not
# reshape a production database — see docs/deployment.md section 5.

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Restore against the project files alone, so a source-only change does not invalidate the
# restore layer.
COPY Messenger.sln ./
COPY src/Messenger.Contracts/Messenger.Contracts.csproj   src/Messenger.Contracts/
COPY src/Messenger.Core/Messenger.Core.csproj             src/Messenger.Core/
COPY src/Messenger.Crypto/Messenger.Crypto.csproj         src/Messenger.Crypto/
COPY src/Messenger.Data/Messenger.Data.csproj             src/Messenger.Data/
COPY src/Messenger.Licensing/Messenger.Licensing.csproj   src/Messenger.Licensing/
COPY src/Messenger.Server/Messenger.Server.csproj         src/Messenger.Server/
RUN dotnet restore src/Messenger.Server/Messenger.Server.csproj

COPY src/ src/
RUN dotnet publish src/Messenger.Server/Messenger.Server.csproj \
      --configuration Release \
      --no-restore \
      --output /app

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app

# The key store and file store are the two pieces of state that must outlive the container.
# Created here and owned by the runtime user so a mounted volume inherits a sane owner; both
# are declared as volumes so an operator who forgets to mount them gets a warning from Docker
# rather than silent data loss on the next `docker rm`.
RUN useradd --system --uid 64123 --create-home --home-dir /home/messenger messenger \
 && mkdir -p /var/lib/messenger/keystore /var/lib/messenger/filestore \
 && chown -R messenger:messenger /var/lib/messenger

COPY --from=build --chown=messenger:messenger /app ./

USER messenger

ENV ASPNETCORE_URLS=http://+:8080 \
    KeyStore__EscrowPath=/var/lib/messenger/keystore/root.escrow \
    AuditSigningKey__EscrowPath=/var/lib/messenger/keystore/audit-signing.escrow \
    FileStore__RootPath=/var/lib/messenger/filestore \
    DOTNET_gcServer=1

VOLUME ["/var/lib/messenger/keystore", "/var/lib/messenger/filestore"]
EXPOSE 8080

# Readiness, not liveness: the question a scheduler needs answered is "can this instance
# serve a request", and for this server that means the database is reachable.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/bin/sh", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080 && printf 'GET /health/ready HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n' >&3 && grep -q Healthy <&3"]

ENTRYPOINT ["dotnet", "Messenger.Server.dll"]

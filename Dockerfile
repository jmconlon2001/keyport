# syntax=docker/dockerfile:1
# Keyport: single self-contained container (Kestrel edge + internal CA + UI + API).
# Works with Podman (`podman build`) and Docker.

ARG DOTNET_VERSION=10.0

# ---------- build ----------
FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
WORKDIR /src

# Restore first to warm the NuGet cache layer.
COPY Keyport.sln ./
COPY src/Keyport.Core/Keyport.Core.csproj src/Keyport.Core/
COPY src/Keyport.Server/Keyport.Server.csproj src/Keyport.Server/
RUN dotnet restore src/Keyport.Server/Keyport.Server.csproj

COPY src/ src/
# NOTE: no --no-restore. The SDK only adds the Blazor framework-asset package (blazor.web.js) when it can
# see .razor files, which are absent during the cache-layer restore above.
RUN dotnet publish src/Keyport.Server/Keyport.Server.csproj \
        -c Release -o /app \
        /p:UseAppHost=false /p:DebugType=none /p:GenerateDocumentationFile=false \
 && test -f /app/wwwroot/_framework/blazor.web.js

# Data dir owned by the non-root app user (UID 1654 in the chiseled images).
RUN mkdir -p /data && chown 1654:1654 /data

# ---------- runtime ----------
# Chiseled = distroless Ubuntu: no shell, no package manager, non-root by default.
# "-extra" adds ICU + tzdata, required by Microsoft.Data.SqlClient (no invariant globalization).
FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION}-noble-chiseled-extra AS runtime

LABEL org.opencontainers.image.title="Keyport" \
      org.opencontainers.image.description="Secrets service for Oracle/SQL Server connection strings and credentials with per-environment ports, built-in TLS CA and audit trail."

WORKDIR /app
COPY --from=build /app ./
COPY --from=build --chown=1654:1654 /data /data

ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_HTTP_PORTS= \
    DOTNET_RUNNING_IN_CONTAINER=true \
    DOTNET_gcServer=0 \
    Keyport__DataPath=/data \
    Keyport__MasterKeyFile=/run/secrets/keyport_master_key

USER 1654

# 8080 = HTTP bootstrap (CA download, health, redirect) · 8443 = admin UI
# 9443 Dev · 9444 Test · 9445 Upgrade · 9446 Prod
EXPOSE 8080 8443 9443 9444 9445 9446
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["dotnet", "Keyport.Server.dll", "--healthcheck"]

ENTRYPOINT ["dotnet", "Keyport.Server.dll"]

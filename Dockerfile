# Multi-stage build for the ghidra-mcp remote connector.
#
#   Stage 1 (builder): Temurin 21 + Node 20 + Ghidra. Builds the TS packages
#     (pnpm workspace) and the Java worker fat-JAR (compiled against Ghidra).
#   Stage 2 (runtime): Temurin 21 + Node 20 + Ghidra + the built artifacts.
#     The daemon (Node) spawns one `java … com.ghidramcp.Worker` per session, so
#     the runtime image needs all three: Node, a JRE, and a Ghidra install.
#
# Build is amd64 in CI (GitHub runners) — the cluster nodes are x86.

# ----------------------------------------------------------------------------
FROM eclipse-temurin:21-jdk AS builder
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl unzip ca-certificates gnupg \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && corepack enable \
 && rm -rf /var/lib/apt/lists/*

# Ghidra — needed at build time to compile the worker against its API jars,
# and at runtime for the worker classpath. MUST match the Ghidra Server version
# (ghcr.io/jaenster/ghidra-server) — the RMI client/server handshake is version-checked.
ENV GHIDRA_HOME=/opt/ghidra
RUN curl -fsSL -o /tmp/ghidra.zip \
      https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.2_build/ghidra_12.1.2_PUBLIC_20260605.zip \
 && unzip -q /tmp/ghidra.zip -d /opt \
 && rm /tmp/ghidra.zip \
 && mv /opt/ghidra_12.1.2_PUBLIC /opt/ghidra

WORKDIR /app
COPY . .

# TS packages (pnpm builds in topological order) and the worker JAR.
RUN pnpm install --frozen-lockfile
RUN pnpm -r build
RUN cd ghidra-worker && ./gradlew --no-daemon --console=plain build

# ----------------------------------------------------------------------------
FROM eclipse-temurin:21-jdk

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates gnupg fontconfig procps \
 && curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
 && apt-get install -y --no-install-recommends nodejs \
 && rm -rf /var/lib/apt/lists/*

ENV GHIDRA_HOME=/opt/ghidra
COPY --from=builder /opt/ghidra /opt/ghidra

WORKDIR /app
# Built TS output + pnpm-linked deps + the worker fat-JAR.
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/packages ./packages
COPY --from=builder /app/package.json /app/pnpm-workspace.yaml ./
COPY --from=builder /app/ghidra-worker/build/libs/ ./ghidra-worker/build/libs/

# Persistent app data (state.db, worker-secret, projects) lives under $HOME;
# the k8s PVC is mounted at /data. 0.0.0.0 so the Service/ingress can reach it.
ENV HOME=/data \
    GHIDRA_MCP_HOST=0.0.0.0 \
    GHIDRA_MCP_PORT=8432
RUN mkdir -p /data

EXPOSE 8432
CMD ["node", "packages/cli/dist/index.js", "start", "-p", "8432", "-f"]

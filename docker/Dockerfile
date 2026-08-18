# syntax=docker/dockerfile:1.7
#
# Container image for the dsh web surface, built from source.
#
# Source build rather than the published `@deepseek-ai/dsh` npm artifact: the
# pluggable web-authentication capability this image relies on is on master but
# not in any npm release yet.
#
# The image never patches installed files. Binding beyond loopback goes through
# the official patch layer (`--patch`), because `dsh web --host 0.0.0.0` is
# refused by the CLI on purpose, and remote callers are admitted by the
# in-product `ctx.webAuth` seam rather than by an external gateway.
#
# The stages are split so that the dependency tree — around 90% of the image —
# is decided by the lockfile alone. A source-only change then leaves that layer's
# digest untouched, and a deployment re-pulls tens of megabytes instead of the
# whole workspace.

ARG NODE_IMAGE=node:24-bookworm-slim
# The registry the build fetches from. The lockfile pins name, version and
# integrity, so a mirror serving the same tarballs changes nothing but latency.
ARG NPM_REGISTRY=https://registry.npmmirror.com/

# Narrows the context to the files that decide the dependency graph. Installing
# from this instead of from the whole workspace is what keeps the install — and
# the tree it produces — identical across source-only rebuilds.
FROM ${NODE_IMAGE} AS manifests
WORKDIR /src
COPY . .
# The two lifecycle scripts are the workspace's install-time hooks: the root
# `postinstall` and subprocess-local's. A third one has to be added here, and
# announces itself by failing the install below.
RUN set -eu; \
    mkdir -p /manifests; \
    find . -name node_modules -prune -o -name package.json -print \
      | xargs -I{} cp --parents {} /manifests/; \
    cp --parents pnpm-lock.yaml pnpm-workspace.yaml /manifests/; \
    cp --parents -r patches /manifests/; \
    cp --parents scripts/install-lefthook.mjs /manifests/; \
    cp --parents packages/subprocess/subprocess-local/scripts/ensure-spawn-helper.mjs /manifests/

FROM ${NODE_IMAGE} AS deps
ARG NPM_REGISTRY
ENV PNPM_HOME=/pnpm \
    PATH=/pnpm:$PATH \
    CI=1
# node-pty and koffi compile during install; the toolchain stays in this stage.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential ca-certificates git pkg-config python3 \
    && rm -rf /var/lib/apt/lists/*
RUN corepack enable
WORKDIR /src
RUN printf '%s\n' \
      'store-dir=/pnpm/store' \
      "registry=${NPM_REGISTRY}" \
      'fetch-timeout=300000' \
      'fetch-retries=6' \
      'network-concurrency=12' > /src/.npmrc
COPY --from=manifests /manifests /src
# The pnpm store is a cache mount, so a rebuild after a source edit re-resolves
# nothing. `--frozen-lockfile` is what CI uses, so a stale lockfile fails here too.
# `--trust-lockfile` skips re-applying the supply-chain policy to all 1203 lockfile
# entries — six minutes of registry round-trips for a lockfile the repository and
# its CI already verify.
RUN --mount=type=cache,target=/pnpm/store,sharing=locked \
    pnpm install --frozen-lockfile --trust-lockfile

FROM deps AS builder
# `.dockerignore` drops every node_modules, so the installed tree survives this.
COPY . .
RUN pnpm run build
# The dependency tree ships from `deps` instead, so that the layer below carries
# only what a source change actually rewrites.
RUN rm -rf /src/node_modules

FROM ${NODE_IMAGE} AS runtime
# bash, git and ripgrep are the harness's own tool surface; curl serves the
# healthcheck; tini reaps the processes the agent spawns.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl git ripgrep tini \
    && rm -rf /var/lib/apt/lists/*

ENV DSH_HOME=/dsh-home \
    DSH_TELEMETRY_MODE=DISABLED \
    NODE_ENV=production

# Two layers rather than one. The first turns over with the lockfile, the second
# with the source; the per-package `node_modules` symlink farms travel with the
# source layer, and resolve because the root tree lands at the same relative path.
COPY --from=deps /src/node_modules /opt/dsh/node_modules
COPY --from=builder /src /opt/dsh
COPY docker/entrypoint.sh /usr/local/bin/dsh-entrypoint
RUN chmod +x /usr/local/bin/dsh-entrypoint \
    && mkdir -p /dsh-home /workspace \
    && chown -R node:node /dsh-home /workspace

# uid 1000 (`node`): the agent runs arbitrary code, so it does not run as root.
# Mounted volumes must be writable by uid 1000.
USER node
WORKDIR /workspace
EXPOSE 3080

# Loopback probe: inside the container this is a loopback authority, which the
# trust fence admits without a credential even when authentication is required.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${DSH_PORT:-3080}/" > /dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/dsh-entrypoint"]

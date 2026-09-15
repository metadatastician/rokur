# SPDX-License-Identifier: MPL-2.0
# Containerfile — Multi-stage build for Rokur secrets management gate.
# Runtime: Bun on Chainguard Wolfi base.

# ---------------------------------------------------------------------------
# Stage 1: Build — install the Bun runtime
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS build

RUN apk add --no-cache curl unzip

# Install Bun (pinned version for reproducibility).
#
# `unzip -j ... -d DIR`, never `install`: /usr/local/bin does not exist in
# wolfi-base. `unzip -d` creates it; `install` without -D does not. `-j` junks
# the archive path because bun's zip nests its binary under bun-linux-x64/.
#
# The trailing `bun --version` is deliberate and load-bearing: it makes a
# wrong-architecture or truncated download fail at BUILD time rather than at
# the first request in production.
ARG BUN_VERSION=1.4.1
RUN curl -fsSL "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/bun-linux-x64.zip" \
        -o /tmp/bun.zip \
    && unzip -j /tmp/bun.zip 'bun-linux-x64/bun' -d /usr/local/bin \
    && rm /tmp/bun.zip \
    && chmod +x /usr/local/bin/bun \
    && /usr/local/bin/bun --version

# Install dependencies from the lockfile before copying source, so a source-only
# change does not invalidate the dependency layer.
WORKDIR /build
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy application source.
COPY main.js config.js audit.js rate_limit.js ./
COPY policy/ ./policy/

# ---------------------------------------------------------------------------
# Stage 2: Runtime — minimal image with only what is needed
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS runtime

# No `apk add` here, and that is measured rather than assumed: bun needs only
# libc/libdl/libm/libpthread, all glibc and all already present in wolfi-base.
# The deno stage this replaces required `apk add libgcc`; the bun runtime stage
# is strictly simpler.
COPY --from=build /usr/local/bin/bun /usr/local/bin/bun

# Create non-root user for the service.
RUN addgroup -S rokur && adduser -S -G rokur rokur

WORKDIR /app

# Copy application files and the resolved dependency tree.
COPY --from=build /build/main.js /build/config.js /build/audit.js /build/rate_limit.js ./
COPY --from=build /build/policy/ ./policy/
COPY --from=build /build/package.json /build/bun.lock ./
COPY --from=build /build/node_modules/ ./node_modules/

RUN chown -R rokur:rokur /app

USER rokur

# Rokur listens on port 7658 by default (ROKUR_PORT).
EXPOSE 7658

# Health check against the /health endpoint.
#
# `bun -e` rather than curl: this image has NO HTTP client at all. Neither curl
# nor wget is present in wolfi-base, and none is installed above. A `curl -f`
# healthcheck here would fail permanently and mark the container unhealthy
# forever, which is worse than having no healthcheck.
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD bun -e "const r = await fetch('http://127.0.0.1:7658/health'); process.exit(r.ok ? 0 : 1)"

ENTRYPOINT ["bun", "run", "main.js"]

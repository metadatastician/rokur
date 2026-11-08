# SPDX-License-Identifier: MPL-2.0
# Containerfile — Multi-stage build for Rokur secrets management gate.
# Runtime: Bun on Chainguard Wolfi base.

# ---------------------------------------------------------------------------
# Stage 1: Build — install the Bun runtime
# ---------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS build

# wolfi-base already supplies BusyBox tar; coreutils supplies sha512sum.
RUN apk add --no-cache coreutils curl

# Install Bun (pinned version for reproducibility).
#
# The GitHub release asset for 1.4.1 returned HTTP 504 in CI, so retrieve the
# corresponding official @oven registry package instead. It holds the same
# Linux x64 glibc binary, but comes from registry.npmjs.org rather than the
# release-asset CDN. Verify its published SHA-512 before extracting it.
#
# The trailing `bun --version` is deliberate and load-bearing: it makes a
# wrong-architecture, bad digest, or truncated download fail at BUILD time
# rather than at the first request in production.
ARG BUN_VERSION=1.4.1
ARG BUN_TARBALL_SHA512=99ad803bb7ffd1867528b53b2073b4045778d73af231b3c0da1ce0c88c393161bae0c554bc27db29473bfa743ea4b8093881ee03daf4ef98b44d65a504613e04
RUN curl -fsSL --proto '=https' --tlsv1.2 \
        --retry 5 --retry-delay 2 --retry-connrefused \
        "https://registry.npmjs.org/@oven/bun-linux-x64/-/bun-linux-x64-${BUN_VERSION}.tgz" \
        -o /tmp/bun.tgz \
    && echo "${BUN_TARBALL_SHA512}  /tmp/bun.tgz" | sha512sum -c - \
    && mkdir -p /usr/local/bin \
    && tar -xzf /tmp/bun.tgz -C /tmp \
    && mv /tmp/package/bin/bun /usr/local/bin/bun \
    && rm -rf /tmp/bun.tgz /tmp/package \
    && chmod +x /usr/local/bin/bun \
    && /usr/local/bin/bun --version

# Install dependencies from the lockfile before copying source, so a source-only
# change does not invalidate the dependency layer.
WORKDIR /build
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production --ignore-scripts

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

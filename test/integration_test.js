// SPDX-License-Identifier: MPL-2.0
// Integration tests for Rokur HTTP server.
// Starts the actual server and tests all endpoints.

import { afterAll, beforeAll, describe, expect, it } from "bun:test";

// Integration tests manage server subprocesses across beforeAll/afterAll
// boundaries; the subprocess deliberately outlives the assertions.

const TEST_PORT = 19090;
const BASE_URL = `http://127.0.0.1:${TEST_PORT}`;
const API_TOKEN = "test-token-rokur-integration";

let serverProcess;

async function waitForServer(url, maxAttempts = 30) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const response = await fetch(`${url}/health`);
      if (response.ok) return;
    } catch {
      // Server not ready yet.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Server at ${url} did not become ready`);
}

describe("Rokur HTTP integration", () => {
  beforeAll(async () => {
    //  process.execPath is the bun binary running this suite; bun is not on
    //  PATH in every environment, so spawning "bun" by name is not safe.
    serverProcess = Bun.spawn([process.execPath, "main.js"], {
      cwd: new URL("..", import.meta.url).pathname,
      env: {
        ...process.env,
        ROKUR_HOST: "127.0.0.1",
        ROKUR_PORT: String(TEST_PORT),
        ROKUR_ENV: "development",
        ROKUR_API_TOKEN: API_TOKEN,
        ROKUR_REQUIRED_SECRETS: "db_password,api_key",
        ROKUR_SECRET_DB_PASSWORD: "hunter2",
        ROKUR_SECRET_API_KEY: "key-abc-123",
        ROKUR_AUDIT_LOG: "false",
        ROKUR_REQUEST_LOG: "false",
        ROKUR_RATE_LIMIT_MAX: "1000",
      },
      stdout: "ignore",
      stderr: "ignore",
    });

    await waitForServer(BASE_URL);
  });

  afterAll(() => {
    try {
      serverProcess.kill("SIGTERM");
    } catch {
      // Already exited.
    }
  });

  // -----------------------------------------------------------------------
  // GET /health
  // -----------------------------------------------------------------------

  it("GET /health returns 200 with service info", async () => {
    const response = await fetch(`${BASE_URL}/health`);
    expect(response.status).toEqual(200);

    const body = await response.json();
    expect(body.status).toEqual("ok");
    expect(body.service).toEqual("rokur");
    expect(body.policyConfigured).toEqual(true);
    expect(body.tokenAuthEnabled).toEqual(true);
    expect(body.requiredSecretCount).toEqual(2);
    expect(body.timestamp).toBeDefined();
    expect(body.version).toBeDefined();
  });

  it("GET /health does not require authentication", async () => {
    const response = await fetch(`${BASE_URL}/health`);
    expect(response.status).toEqual(200);
  });

  it("GET /health returns x-request-id header", async () => {
    const response = await fetch(`${BASE_URL}/health`);
    const requestId = response.headers.get("x-request-id");
    expect(requestId).toBeDefined();
    expect(requestId.length > 0).toEqual(true);
  });

  it("GET /health forwards provided x-request-id", async () => {
    const response = await fetch(`${BASE_URL}/health`, {
      headers: { "x-request-id": "custom-id-12345" },
    });
    const requestId = response.headers.get("x-request-id");
    expect(requestId).toEqual("custom-id-12345");
  });

  // -----------------------------------------------------------------------
  // GET /v1/secrets/status
  // -----------------------------------------------------------------------

  it("GET /v1/secrets/status returns 200 when all secrets present", async () => {
    const response = await fetch(`${BASE_URL}/v1/secrets/status`, {
      headers: { "x-rokur-token": API_TOKEN },
    });
    expect(response.status).toEqual(200);

    const body = await response.json();
    expect(body.allowed).toEqual(true);
    expect(body.policy).toEqual("allow");
    expect(body.code).toEqual("AUTHORIZED");
    expect(body.requiredSecretCount).toEqual(2);
    expect(body.missingSecretCount).toEqual(0);
    expect(body.requestId).toBeDefined();
  });

  it("GET /v1/secrets/status returns 401 without token", async () => {
    const response = await fetch(`${BASE_URL}/v1/secrets/status`);
    expect(response.status).toEqual(401);

    const body = await response.json();
    expect(body.error).toEqual("Unauthorized");
  });

  it("GET /v1/secrets/status returns 401 with wrong token", async () => {
    const response = await fetch(`${BASE_URL}/v1/secrets/status`, {
      headers: { "x-rokur-token": "wrong-token" },
    });
    expect(response.status).toEqual(401);
  });

  // -----------------------------------------------------------------------
  // POST /v1/authorize-start
  // -----------------------------------------------------------------------

  it("POST /v1/authorize-start returns 200 with valid request", async () => {
    const response = await fetch(`${BASE_URL}/v1/authorize-start`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-rokur-token": API_TOKEN,
      },
      body: JSON.stringify({ image: "alpine:3.19", name: "my-container" }),
    });
    expect(response.status).toEqual(200);

    const body = await response.json();
    expect(body.allowed).toEqual(true);
    expect(body.image).toEqual("alpine:3.19");
    expect(body.name).toEqual("my-container");
    expect(body.policyEngine).toEqual("builtin");
    expect(body.decisionTimestamp).toBeDefined();
    expect(body.requestId).toBeDefined();
  });

  it("POST /v1/authorize-start returns 401 without token", async () => {
    const response = await fetch(`${BASE_URL}/v1/authorize-start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ image: "alpine:3.19" }),
    });
    expect(response.status).toEqual(401);
  });

  it("POST /v1/authorize-start returns 400 with invalid JSON", async () => {
    const response = await fetch(`${BASE_URL}/v1/authorize-start`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-rokur-token": API_TOKEN,
      },
      body: "not json",
    });
    expect(response.status).toEqual(400);

    const body = await response.json();
    expect(body.error).toEqual("Invalid JSON body");
  });

  it("POST /v1/authorize-start handles missing image/name gracefully", async () => {
    const response = await fetch(`${BASE_URL}/v1/authorize-start`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-rokur-token": API_TOKEN,
      },
      body: JSON.stringify({}),
    });
    expect(response.status).toEqual(200);

    const body = await response.json();
    expect(body.allowed).toEqual(true);
    expect(body.image).toEqual(null);
    expect(body.name).toEqual(null);
  });

  // -----------------------------------------------------------------------
  // GET /metrics
  // -----------------------------------------------------------------------

  it("GET /metrics returns counters and config", async () => {
    const response = await fetch(`${BASE_URL}/metrics`);
    expect(response.status).toEqual(200);

    const body = await response.json();
    expect(body.service).toEqual("rokur");
    expect(body.uptime_ms).toBeDefined();
    expect(body.started_at).toBeDefined();
    expect(typeof body.requests_total).toEqual("number");
    expect(typeof body.authorizations_allowed).toEqual("number");
    expect(typeof body.authorizations_denied).toEqual("number");
    expect(typeof body.auth_failures).toEqual("number");
    expect(body.required_secret_count).toEqual(2);
    expect(body.rate_limiter).toBeDefined();
  });

  it("GET /metrics does not require authentication", async () => {
    const response = await fetch(`${BASE_URL}/metrics`);
    expect(response.status).toEqual(200);
  });

  // -----------------------------------------------------------------------
  // POST /v1/secrets/reload
  // -----------------------------------------------------------------------

  it("POST /v1/secrets/reload requires authentication", async () => {
    const response = await fetch(`${BASE_URL}/v1/secrets/reload`, {
      method: "POST",
    });
    expect(response.status).toEqual(401);
  });

  it("POST /v1/secrets/reload succeeds with valid token", async () => {
    const response = await fetch(`${BASE_URL}/v1/secrets/reload`, {
      method: "POST",
      headers: { "x-rokur-token": API_TOKEN },
    });
    expect(response.status).toEqual(200);

    const body = await response.json();
    expect(body.status).toEqual("reloaded");
    expect(typeof body.previousRequiredSecretCount).toEqual("number");
    expect(typeof body.currentRequiredSecretCount).toEqual("number");
    expect(body.requestId).toBeDefined();
  });

  // -----------------------------------------------------------------------
  // 404 handling
  // -----------------------------------------------------------------------

  it("returns 404 for unknown paths", async () => {
    const response = await fetch(`${BASE_URL}/unknown/path`);
    expect(response.status).toEqual(404);

    const body = await response.json();
    expect(body.error).toEqual("Not Found");
    expect(body.path).toEqual("/unknown/path");
  });

  it("returns 404 for wrong HTTP method", async () => {
    const response = await fetch(`${BASE_URL}/v1/authorize-start`);
    expect(response.status).toEqual(404);
  });

  // -----------------------------------------------------------------------
  // Request ID propagation
  // -----------------------------------------------------------------------

  it("generates request ID when none provided", async () => {
    const response = await fetch(`${BASE_URL}/v1/secrets/status`, {
      headers: { "x-rokur-token": API_TOKEN },
    });
    const requestId = response.headers.get("x-request-id");
    expect(requestId).toBeDefined();

    const body = await response.json();
    expect(body.requestId).toEqual(requestId);
  });

  it("uses provided request ID", async () => {
    const response = await fetch(`${BASE_URL}/v1/secrets/status`, {
      headers: {
        "x-rokur-token": API_TOKEN,
        "x-request-id": "trace-abc-999",
      },
    });
    expect(response.headers.get("x-request-id")).toEqual("trace-abc-999");

    const body = await response.json();
    expect(body.requestId).toEqual("trace-abc-999");
  });
});

describe("Rokur with missing secrets", () => {
  let serverProcess;
  const port = 19091;
  const url = `http://127.0.0.1:${port}`;

  beforeAll(async () => {
    //  process.execPath is the bun binary running this suite; bun is not on
    //  PATH in every environment, so spawning "bun" by name is not safe.
    serverProcess = Bun.spawn([process.execPath, "main.js"], {
      cwd: new URL("..", import.meta.url).pathname,
      env: {
        ...process.env,
        ROKUR_HOST: "127.0.0.1",
        ROKUR_PORT: String(port),
        ROKUR_ENV: "development",
        ROKUR_ALLOW_UNAUTHENTICATED: "true",
        ROKUR_REQUIRED_SECRETS: "db_password,api_key",
        ROKUR_SECRET_DB_PASSWORD: "present",
        // api_key deliberately NOT set
        ROKUR_AUDIT_LOG: "false",
        ROKUR_REQUEST_LOG: "false",
      },
      stdout: "ignore",
      stderr: "ignore",
    });

    // Wait for server readiness.
    for (let i = 0; i < 30; i++) {
      try {
        const res = await fetch(`${url}/health`);
        if (res.ok) break;
      } catch { /* not ready */ }
      await new Promise((r) => setTimeout(r, 100));
    }
  });

  afterAll(() => {
    try {
      serverProcess.kill("SIGTERM");
    } catch { /* noop */ }
  });

  it("returns 409 when secrets are missing", async () => {
    const response = await fetch(`${url}/v1/secrets/status`);
    expect(response.status).toEqual(409);

    const body = await response.json();
    expect(body.allowed).toEqual(false);
    expect(body.policy).toEqual("deny");
    expect(body.missingSecretCount).toEqual(1);
  });

  it("authorize-start also denies with missing secrets", async () => {
    const response = await fetch(`${url}/v1/authorize-start`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ image: "nginx:latest" }),
    });
    expect(response.status).toEqual(409);

    const body = await response.json();
    expect(body.allowed).toEqual(false);
    expect(body.image).toEqual("nginx:latest");
  });
});

// SPDX-License-Identifier: MPL-2.0
// Integration tests for booting rokur FROM A CONFIG FILE.
//
// The unit tests in config_toml_test.js prove the loader parses and rejects
// correctly. These prove the binary actually honours the file end-to-end:
// a real subprocess, a real socket, a port and health path that exist ONLY in
// the TOML and in no environment variable.

import { afterAll, beforeAll, describe, expect, it } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const FILE_PORT = 19096;
const BASE_URL = `http://127.0.0.1:${FILE_PORT}`;
const REPO_ROOT = new URL("..", import.meta.url).pathname;

let serverProcess;
let configPath;
let configDir;

async function waitFor(url, maxAttempts = 40) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const r = await fetch(url);
      if (r.ok) return r;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`${url} did not become ready`);
}

describe("rokur boots from rokur.toml", () => {
  beforeAll(async () => {
    configDir = mkdtempSync(join(tmpdir(), "rokur-cfg-"));
    configPath = join(configDir, "rokur.toml");
    //  Port and health path exist ONLY here. If rokur ignored the file, it
    //  would bind 7658 and serve /health, and every assertion below fails.
    writeFileSync(
      configPath,
      `[metadata]
name = "rokur-file-test"

[server]
host = "127.0.0.1"
port = ${FILE_PORT}
health_path = "/healthz"

[secrets]
required = ["DB_PASSWORD"]

[rate_limit]
max = 1000
`,
    );

    //  process.execPath is the bun binary running this suite; bun is not on
    //  PATH in every environment, so spawning "bun" by name is not safe.
    serverProcess = Bun.spawn([
      process.execPath,
      "main.js",
      "--config",
      configPath,
    ], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        //  Deliberately NOT setting ROKUR_PORT or ROKUR_HEALTH_PATH: the file
        //  must be the only source of both.
        //  Empty, not unset: this also exercises the envOr() rule that an
        //  empty env var means "absent" and must not shadow the file.
        ROKUR_PORT: "",
        ROKUR_REQUIRED_SECRETS: "",
        ROKUR_ENV: "development",
        ROKUR_API_TOKEN: "test-token-file",
        //  rokur refuses to start unless every required secret is present.
        //  The requirement itself comes from the TOML above, so this proves
        //  the file drives startup validation, not just the listen address.
        ROKUR_SECRET_DB_PASSWORD: "hunter2",
        ROKUR_AUDIT_LOG: "false",
        ROKUR_REQUEST_LOG: "false",
      },
      stdout: "ignore",
      stderr: "ignore",
    });

    await waitFor(`${BASE_URL}/healthz`);
  });

  //  Synchronous, and deliberately does NOT await serverProcess.status --
  //  matching test/integration_test.js. Awaiting the exit hangs the run:
  //  rokur installs a SIGTERM handler for graceful shutdown that does not
  //  resolve here, so the await never returns: the subprocess deliberately
  //  outlives the assertions.
  afterAll(() => {
    try {
      serverProcess.kill("SIGTERM");
    } catch { /* already exited */ }
    try {
      rmSync(configDir, { recursive: true, force: true });
    } catch { /* already gone */ }
  });

  it("binds the port given only in the TOML", async () => {
    const r = await fetch(`${BASE_URL}/healthz`);
    expect(r.status).toEqual(200);
    await r.body?.cancel();
  });

  it("takes required secrets from the TOML", async () => {
    //  The server refuses to start with zero required secrets, and none were
    //  given in the environment -- so a listening server proves the file's
    //  [secrets] required list was applied.
    const r = await fetch(`${BASE_URL}/healthz`);
    expect(r.status).toEqual(200);
    await r.body?.cancel();
  });

  it("serves the health path given only in the TOML", async () => {
    //  /health is the built-in default; the file moved it to /healthz, so the
    //  default must now 404. This is what distinguishes "read the file" from
    //  "happened to work".
    const r = await fetch(`${BASE_URL}/health`);
    expect(r.status).toEqual(404);
    await r.body?.cancel();
  });
});

describe("rokur refuses to start on a bad config file", () => {
  it("exits non-zero rather than starting with a half-read policy", async () => {
    const badDir = mkdtempSync(join(tmpdir(), "rokur-bad-"));
    const badPath = join(badDir, "rokur.toml");
    //  [server] backend is the rejection that matters most: it is what the
    //  bundle used to specify, and accepting it would imply rokur proxies.
    writeFileSync(badPath, `[server]\nbackend = "http://app:8080"\n`);

    const proc = Bun.spawn(
      [process.execPath, "main.js", "--config", badPath],
      {
        cwd: REPO_ROOT,
        env: { ...process.env, ROKUR_ENV: "development" },
        stdout: "ignore",
        stderr: "pipe",
      },
    );

    //  Bun.spawn has no .output(): drain stderr, then await the exit code.
    const message = await new Response(proc.stderr).text();
    const code = await proc.exited;

    expect(code, `expected exit 1, got ${code}. stderr: ${message}`).toEqual(1);
    expect(message.includes("refusing to start"), `expected a refusal on stderr, got: ${message}`).toEqual(true);

    rmSync(badDir, { recursive: true, force: true });
  });
});

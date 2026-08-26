// SPDX-License-Identifier: MPL-2.0
// Integration tests for booting rokur FROM A CONFIG FILE.
//
// The unit tests in config_toml_test.js prove the loader parses and rejects
// correctly. These prove the binary actually honours the file end-to-end:
// a real subprocess, a real socket, a port and health path that exist ONLY in
// the TOML and in no environment variable.

import { assertEquals } from "@std/assert";
import { afterAll, beforeAll, describe, it } from "@std/testing/bdd";

const suiteOpts = { sanitizeResources: false, sanitizeOps: false };

const FILE_PORT = 19096;
const BASE_URL = `http://127.0.0.1:${FILE_PORT}`;
const REPO_ROOT = new URL("..", import.meta.url).pathname;

let serverProcess;
let configPath;

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

describe("rokur boots from rokur.toml", suiteOpts, () => {
  beforeAll(async () => {
    configPath = Deno.makeTempFileSync({ suffix: ".toml" });
    //  Port and health path exist ONLY here. If rokur ignored the file, it
    //  would bind 9090 and serve /health, and every assertion below fails.
    Deno.writeTextFileSync(
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

    serverProcess = new Deno.Command("deno", {
      args: ["run", "--allow-net", "--allow-env", "--allow-read", "main.js", "--config", configPath],
      cwd: REPO_ROOT,
      env: {
        ...Deno.env.toObject(),
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
      stdout: "null",
      stderr: "null",
    }).spawn();

    await waitFor(`${BASE_URL}/healthz`);
  });

  //  Synchronous, and deliberately does NOT await serverProcess.status --
  //  matching test/integration_test.js. Awaiting the exit hangs the run:
  //  rokur installs a SIGTERM handler for graceful shutdown that does not
  //  resolve here, so the await never returns. Sanitizers are off for this
  //  suite precisely because the subprocess outlives the assertions.
  afterAll(() => {
    try {
      serverProcess.kill("SIGTERM");
    } catch { /* already exited */ }
    try {
      Deno.removeSync(configPath);
    } catch { /* already gone */ }
  });

  it("binds the port given only in the TOML", async () => {
    const r = await fetch(`${BASE_URL}/healthz`);
    assertEquals(r.status, 200);
    await r.body?.cancel();
  });

  it("takes required secrets from the TOML", async () => {
    //  The server refuses to start with zero required secrets, and none were
    //  given in the environment -- so a listening server proves the file's
    //  [secrets] required list was applied.
    const r = await fetch(`${BASE_URL}/healthz`);
    assertEquals(r.status, 200);
    await r.body?.cancel();
  });

  it("serves the health path given only in the TOML", async () => {
    //  /health is the built-in default; the file moved it to /healthz, so the
    //  default must now 404. This is what distinguishes "read the file" from
    //  "happened to work".
    const r = await fetch(`${BASE_URL}/health`);
    assertEquals(r.status, 404);
    await r.body?.cancel();
  });
});

describe("rokur refuses to start on a bad config file", suiteOpts, () => {
  it("exits non-zero rather than starting with a half-read policy", async () => {
    const badPath = Deno.makeTempFileSync({ suffix: ".toml" });
    //  [server] backend is the rejection that matters most: it is what the
    //  bundle used to specify, and accepting it would imply rokur proxies.
    Deno.writeTextFileSync(badPath, `[server]\nbackend = "http://app:8080"\n`);

    const proc = new Deno.Command("deno", {
      args: ["run", "--allow-net", "--allow-env", "--allow-read", "main.js", "--config", badPath],
      cwd: REPO_ROOT,
      env: { ...Deno.env.toObject(), ROKUR_ENV: "development" },
      stdout: "null",
      stderr: "piped",
    }).spawn();

    const { code, stderr } = await proc.output();
    const message = new TextDecoder().decode(stderr);

    assertEquals(code, 1, `expected exit 1, got ${code}. stderr: ${message}`);
    assertEquals(
      message.includes("refusing to start"),
      true,
      `expected a refusal on stderr, got: ${message}`,
    );

    Deno.removeSync(badPath);
  });
});

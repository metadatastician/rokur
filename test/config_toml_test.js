// SPDX-License-Identifier: MPL-2.0
// Tests for rokur.toml loading: the bundle-consumption contract.
//
// The contract has three parts, and each gets a test that can fail:
//   1. precedence is env > file > default
//   2. anything not fully understood THROWS (fail closed)
//   3. [server] backend is rejected outright -- rokur is not a proxy

import { assert, assertEquals, assertThrows } from "@std/assert";
import { loadConfig, loadTomlFile } from "../config.js";

/** Write a temp TOML file and hand back its path. */
function tmpToml(body) {
  const path = Deno.makeTempFileSync({ suffix: ".toml" });
  Deno.writeTextFileSync(path, body);
  return path;
}

/** Run fn with the given env vars set, restoring them afterwards. */
function withEnv(vars, fn) {
  const saved = new Map();
  for (const [k, v] of Object.entries(vars)) {
    saved.set(k, Deno.env.get(k));
    if (v === undefined) Deno.env.delete(k);
    else Deno.env.set(k, v);
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) Deno.env.delete(k);
      else Deno.env.set(k, v);
    }
  }
}

Deno.test("loadTomlFile: reads a well-formed config", () => {
  const p = tmpToml(`
[metadata]
name = "rokur-gate"

[server]
host = "0.0.0.0"
port = 9090
health_path = "/healthz"

[secrets]
required = ["DB_PASSWORD", "API_KEY"]

[rate_limit]
max = 120
`);
  const cfg = loadTomlFile(p);
  assertEquals(cfg.host, "0.0.0.0");
  assertEquals(cfg.port, 9090);
  assertEquals(cfg.healthPath, "/healthz");
  assertEquals(cfg.requiredSecrets, ["DB_PASSWORD", "API_KEY"]);
  assertEquals(cfg.rateLimitMax, 120);
});

Deno.test("loadTomlFile: REJECTS [server] backend -- rokur is not a proxy", () => {
  const p = tmpToml(`[server]\nbackend = "http://app:8080"\n`);
  const err = assertThrows(() => loadTomlFile(p), Error);
  assert(
    err.message.includes("not a proxy"),
    `expected the proxy explanation, got: ${err.message}`,
  );
});

Deno.test("loadTomlFile: unknown table throws", () => {
  const p = tmpToml(`[nonsense]\nx = 1\n`);
  assertThrows(() => loadTomlFile(p), Error, "unknown table");
});

Deno.test("loadTomlFile: unknown key throws", () => {
  const p = tmpToml(`[server]\nnot_a_key = 1\n`);
  assertThrows(() => loadTomlFile(p), Error, "unknown key");
});

Deno.test("loadTomlFile: wrong type throws", () => {
  const p = tmpToml(`[server]\nport = "9090"\n`);
  assertThrows(() => loadTomlFile(p), Error, "must be number");
});

Deno.test("loadTomlFile: malformed TOML throws", () => {
  const p = tmpToml(`[server\nport = 9090\n`);
  assertThrows(() => loadTomlFile(p), Error, "not valid TOML");
});

Deno.test("loadTomlFile: missing file throws", () => {
  assertThrows(
    () => loadTomlFile("/nonexistent/rokur.toml"),
    Error,
    "cannot read config file",
  );
});

Deno.test("precedence: env BEATS file", () => {
  const p = tmpToml(`[server]\nport = 7777\n`);
  withEnv({ ROKUR_PORT: "8888" }, () => {
    assertEquals(loadConfig({ configPath: p }).port, 8888);
  });
});

Deno.test("precedence: file beats default when env is unset", () => {
  const p = tmpToml(`[server]\nport = 7777\n`);
  withEnv({ ROKUR_PORT: undefined }, () => {
    assertEquals(loadConfig({ configPath: p }).port, 7777);
  });
});

Deno.test("precedence: default applies with neither env nor file", () => {
  withEnv({ ROKUR_PORT: undefined }, () => {
    assertEquals(loadConfig().port, 9090);
  });
});

Deno.test("no config file: behaviour is unchanged (env-only)", () => {
  withEnv({ ROKUR_HOST: "10.0.0.1" }, () => {
    assertEquals(loadConfig().host, "10.0.0.1");
  });
});

Deno.test("required secrets: file list is honoured when env is unset", () => {
  const p = tmpToml(`[secrets]\nrequired = ["ONE", "TWO"]\n`);
  withEnv({ ROKUR_REQUIRED_SECRETS: undefined }, () => {
    assertEquals(loadConfig({ configPath: p }).requiredSecrets, ["ONE", "TWO"]);
  });
});

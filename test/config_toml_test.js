// SPDX-License-Identifier: MPL-2.0
// Tests for rokur.toml loading: the bundle-consumption contract.
//
// The contract has three parts, and each gets a test that can fail:
//   1. precedence is env > file > default
//   2. anything not fully understood THROWS (fail closed)
//   3. [server] backend is rejected outright -- rokur is not a proxy

import { expect, test } from "bun:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadConfig, loadTomlFile } from "../config.js";

/** Write a temp TOML file and hand back its path. */
function tmpToml(body) {
  const dir = mkdtempSync(join(tmpdir(), "rokur-toml-"));
  const path = join(dir, "rokur.toml");
  writeFileSync(path, body);
  return path;
}

/** Run fn with the given env vars set, restoring them afterwards. */
function withEnv(vars, fn) {
  const saved = new Map();
  for (const [k, v] of Object.entries(vars)) {
    saved.set(k, process.env[k]);
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test("loadTomlFile: reads a well-formed config", () => {
  const p = tmpToml(`
[metadata]
name = "rokur-gate"

[server]
host = "0.0.0.0"
port = 7658
health_path = "/healthz"

[secrets]
required = ["DB_PASSWORD", "API_KEY"]

[rate_limit]
max = 120
`);
  const cfg = loadTomlFile(p);
  expect(cfg.host).toEqual("0.0.0.0");
  expect(cfg.port).toEqual(7658);
  expect(cfg.healthPath).toEqual("/healthz");
  expect(cfg.requiredSecrets).toEqual(["DB_PASSWORD", "API_KEY"]);
  expect(cfg.rateLimitMax).toEqual(120);
});

test("loadTomlFile: REJECTS [server] backend -- rokur is not a proxy", () => {
  const p = tmpToml(`[server]\nbackend = "http://app:8080"\n`);
  // expect(fn).toThrow() returns nothing (unlike assertThrows, which returned
  // the error), so the type and the message are asserted as two checks.
  expect(() => loadTomlFile(p)).toThrow(Error);
  expect(() => loadTomlFile(p)).toThrow(/not a proxy/);
});

/** Assert that a rokur.toml body is rejected with a message containing `needle`. */
function assertTomlRejected(body, needle) {
  expect(() => loadTomlFile(tmpToml(body))).toThrow(needle);
}

// Part 2 of the contract: anything not fully understood THROWS. These four
// cases differ ONLY in the file body and the expected message, so the shape is
// written once here and each case keeps its own name and its own failure.
// (Previously four hand-copied blocks -- Sonar CPD, 23 duplicated lines.)
const REJECTED_TOML = [
  [
    "loadTomlFile: unknown table throws",
    "[nonsense]\nx = 1\n",
    "unknown table",
  ],
  [
    "loadTomlFile: unknown key throws",
    "[server]\nnot_a_key = 1\n",
    "unknown key",
  ],
  [
    "loadTomlFile: wrong type throws",
    '[server]\nport = "7658"\n',
    "must be number",
  ],
  [
    "loadTomlFile: malformed TOML throws",
    "[server\nport = 7658\n",
    "not valid TOML",
  ],
];

for (const [name, body, needle] of REJECTED_TOML) {
  test(name, () => assertTomlRejected(body, needle));
}

test("loadTomlFile: missing file throws", () => {
  expect(() => loadTomlFile("/nonexistent/rokur.toml")).toThrow("cannot read config file");
});

test("precedence: env BEATS file", () => {
  const p = tmpToml(`[server]\nport = 7777\n`);
  withEnv({ ROKUR_PORT: "8888" }, () => {
    expect(loadConfig({ configPath: p }).port).toEqual(8888);
  });
});

test("precedence: file beats default when env is unset", () => {
  const p = tmpToml(`[server]\nport = 7777\n`);
  withEnv({ ROKUR_PORT: undefined }, () => {
    expect(loadConfig({ configPath: p }).port).toEqual(7777);
  });
});

test("precedence: default applies with neither env nor file", () => {
  withEnv({ ROKUR_PORT: undefined }, () => {
    expect(loadConfig().port).toEqual(7658);
  });
});

test("no config file: behaviour is unchanged (env-only)", () => {
  withEnv({ ROKUR_HOST: "127.0.0.2" }, () => {
    expect(loadConfig().host).toEqual("127.0.0.2");
  });
});

test("required secrets: file list is honoured when env is unset", () => {
  const p = tmpToml(`[secrets]\nrequired = ["ONE", "TWO"]\n`);
  withEnv({ ROKUR_REQUIRED_SECRETS: undefined }, () => {
    expect(loadConfig({ configPath: p }).requiredSecrets).toEqual(["ONE", "TWO"]);
  });
});

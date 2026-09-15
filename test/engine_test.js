// SPDX-License-Identifier: MPL-2.0
// Unit tests for Rokur policy engine.

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { createPolicyEvaluator } from "../policy/engine.js";

function secretEnvName(secretName) {
  const normalized = secretName.toUpperCase().replace(/[^A-Z0-9]/g, "_");
  return `ROKUR_SECRET_${normalized}`;
}

function setEnv(key, value) {
  process.env[key] = value;
}

function deleteEnv(key) {
  try {
    delete process.env[key];
  } catch { /* noop */ }
}

// Clean up any policy-related env vars before/after each test.
function cleanPolicyEnv() {
  for (
    const key of [
      "ROKUR_POLICY_BACKEND",
      "ROKUR_POLICY_COMMAND",
      "ROKUR_POLICY_COMMAND_ARGS",
      "ROKUR_POLICY_TIMEOUT_MS",
      "ROKUR_SECRET_DB_PASSWORD",
      "ROKUR_SECRET_API_KEY",
      "ROKUR_SECRET_TOKEN",
    ]
  ) {
    deleteEnv(key);
  }
}

describe("createPolicyEvaluator", () => {
  beforeEach(cleanPolicyEnv);
  afterEach(cleanPolicyEnv);

  it("creates evaluator with default builtin backend", () => {
    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["db_password"],
      secretEnvName,
    });

    expect(evaluator.config.resolvedBackend).toEqual("builtin");
    expect(evaluator.config.externalCommandConfigured).toEqual(false);
  });

  it("throws when external backend requested without command", () => {
    setEnv("ROKUR_POLICY_BACKEND", "external");

    expect(() => createPolicyEvaluator({ requiredSecrets: ["x"], secretEnvName })).toThrow("ROKUR_POLICY_BACKEND=external requires ROKUR_POLICY_COMMAND");
  });

  it("throws for invalid backend value", () => {
    setEnv("ROKUR_POLICY_BACKEND", "magic");

    expect(() => createPolicyEvaluator({ requiredSecrets: ["x"], secretEnvName })).toThrow('Invalid ROKUR_POLICY_BACKEND: "magic"');
  });

  it("auto backend resolves to builtin when no command configured", () => {
    setEnv("ROKUR_POLICY_BACKEND", "auto");

    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["x"],
      secretEnvName,
    });

    expect(evaluator.config.resolvedBackend).toEqual("builtin");
  });

  it("auto backend resolves to external when command configured", () => {
    setEnv("ROKUR_POLICY_BACKEND", "auto");
    setEnv("ROKUR_POLICY_COMMAND", "/usr/bin/echo");

    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["x"],
      secretEnvName,
    });

    expect(evaluator.config.resolvedBackend).toEqual("external");
    expect(evaluator.config.externalCommandConfigured).toEqual(true);
  });
});

describe("builtin policy evaluation", () => {
  beforeEach(cleanPolicyEnv);
  afterEach(cleanPolicyEnv);

  it("allows when all required secrets are present", async () => {
    setEnv("ROKUR_SECRET_DB_PASSWORD", "hunter2");
    setEnv("ROKUR_SECRET_API_KEY", "key123");

    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["db_password", "api_key"],
      secretEnvName,
    });

    const decision = await evaluator.evaluate({});

    expect(decision.allowed).toEqual(true);
    expect(decision.code).toEqual("AUTHORIZED");
    expect(decision.engine).toEqual("builtin");
    expect(decision.requiredSecretCount).toEqual(2);
    expect(decision.missingSecretCount).toEqual(0);
  });

  it("denies when a required secret is missing", async () => {
    setEnv("ROKUR_SECRET_DB_PASSWORD", "hunter2");
    // api_key NOT set

    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["db_password", "api_key"],
      secretEnvName,
    });

    const decision = await evaluator.evaluate({});

    expect(decision.allowed).toEqual(false);
    expect(decision.code).toEqual("REQUIRED_SECRETS_MISSING");
    expect(decision.engine).toEqual("builtin");
    expect(decision.requiredSecretCount).toEqual(2);
    expect(decision.missingSecretCount).toEqual(1);
  });

  it("denies when a required secret is blank", async () => {
    setEnv("ROKUR_SECRET_DB_PASSWORD", "  ");

    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["db_password"],
      secretEnvName,
    });

    const decision = await evaluator.evaluate({});

    expect(decision.allowed).toEqual(false);
    expect(decision.missingSecretCount).toEqual(1);
  });

  it("denies when all secrets are missing", async () => {
    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["db_password", "api_key", "token"],
      secretEnvName,
    });

    const decision = await evaluator.evaluate({});

    expect(decision.allowed).toEqual(false);
    expect(decision.missingSecretCount).toEqual(3);
    expect(decision.requiredSecretCount).toEqual(3);
  });

  it("allows with zero required secrets (vacuously true)", async () => {
    const evaluator = createPolicyEvaluator({
      requiredSecrets: [],
      secretEnvName,
    });

    const decision = await evaluator.evaluate({});

    expect(decision.allowed).toEqual(true);
    expect(decision.requiredSecretCount).toEqual(0);
    expect(decision.missingSecretCount).toEqual(0);
  });

  it("normalizes secret names to uppercase env vars", async () => {
    setEnv("ROKUR_SECRET_MY_DB_HOST", "localhost");

    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["my-db-host"],
      secretEnvName,
    });

    const decision = await evaluator.evaluate({});

    expect(decision.allowed).toEqual(true);
  });
});

describe("external policy evaluation", () => {
  beforeEach(cleanPolicyEnv);
  afterEach(cleanPolicyEnv);

  it("calls external command and parses allow response", async () => {
    setEnv("ROKUR_POLICY_BACKEND", "external");
    //  process.execPath, not the literal "bun": bun is not guaranteed to be on
    //  PATH, and the evaluator spawns this command directly.
    setEnv("ROKUR_POLICY_COMMAND", process.execPath);
    setEnv(
      "ROKUR_POLICY_COMMAND_ARGS",
      JSON.stringify(["policy/ephapax_adapter_example.js"]),
    );

    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["test_secret"],
      secretEnvName,
    });

    const decision = await evaluator.evaluate({ image: "alpine:3.19" });

    // The example adapter always allows when missingSecretCount === 0
    expect(decision.allowed).toEqual(true);
    expect(decision.engine).toEqual("external");
  });

  it("fails closed when external command does not exist", async () => {
    setEnv("ROKUR_POLICY_BACKEND", "external");
    setEnv("ROKUR_POLICY_COMMAND", "/nonexistent/command/rokur_test");

    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["test_secret"],
      secretEnvName,
    });

    const decision = await evaluator.evaluate({});

    expect(decision.allowed).toEqual(false);
    expect(decision.engine).toEqual("external");
  });

  it("fails closed on timeout", async () => {
    setEnv("ROKUR_POLICY_BACKEND", "external");
    setEnv("ROKUR_POLICY_COMMAND", "sleep");
    setEnv("ROKUR_POLICY_COMMAND_ARGS", "30");
    setEnv("ROKUR_POLICY_TIMEOUT_MS", "200");

    const evaluator = createPolicyEvaluator({
      requiredSecrets: ["test_secret"],
      secretEnvName,
    });

    const decision = await evaluator.evaluate({});

    expect(decision.allowed).toEqual(false);
    expect(decision.engine).toEqual("external");
  });

  it("parses command args from JSON array", () => {
    setEnv("ROKUR_POLICY_BACKEND", "external");
    setEnv("ROKUR_POLICY_COMMAND", "echo");
    setEnv("ROKUR_POLICY_COMMAND_ARGS", '["--flag","value"]');

    const evaluator = createPolicyEvaluator({
      requiredSecrets: [],
      secretEnvName,
    });

    expect(evaluator.config.resolvedBackend).toEqual("external");
  });

  it("parses command args from CSV", () => {
    setEnv("ROKUR_POLICY_BACKEND", "external");
    setEnv("ROKUR_POLICY_COMMAND", "echo");
    setEnv("ROKUR_POLICY_COMMAND_ARGS", "--flag,value");

    const evaluator = createPolicyEvaluator({
      requiredSecrets: [],
      secretEnvName,
    });

    expect(evaluator.config.resolvedBackend).toEqual("external");
  });
});

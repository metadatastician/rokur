// SPDX-License-Identifier: MPL-2.0
import { parse as parseToml } from "@std/toml";
// Rokur configuration — centralised environment variable parsing.
//
// All Deno.env.get() calls for Rokur configuration are consolidated here.
// Call loadConfig() at startup and again on SIGHUP to pick up changes.

/**
 * Parses a boolean from an environment variable.
 *
 * Accepts: true/false, 1/0, yes/no, on/off (case-insensitive).
 * Returns the defaultValue when the variable is unset or empty.
 * Throws on unrecognised values.
 *
 * @param {string} name - Environment variable name.
 * @param {boolean} defaultValue - Value when the variable is absent.
 * @returns {boolean}
 */
function parseBooleanEnv(name, defaultValue = false) {
  const rawValue = Deno.env.get(name);
  if (
    rawValue === undefined || rawValue === null || rawValue.trim().length === 0
  ) {
    return defaultValue;
  }

  const normalized = rawValue.trim().toLowerCase();
  if (
    normalized === "1" || normalized === "true" || normalized === "yes" ||
    normalized === "on"
  ) {
    return true;
  }
  if (
    normalized === "0" || normalized === "false" || normalized === "no" ||
    normalized === "off"
  ) {
    return false;
  }

  throw new Error(
    `Invalid boolean value for ${name}: "${rawValue}". Use true/false, 1/0, yes/no, or on/off.`,
  );
}

/**
 * Parses ROKUR_REQUIRED_SECRETS into a deduplicated array.
 *
 * @returns {string[]}
 */
function parseRequiredSecrets(fileValue) {
  const raw = Deno.env.get("ROKUR_REQUIRED_SECRETS");
  // env wins; else the file's array verbatim; else empty
  if ((raw ?? "").trim().length === 0 && Array.isArray(fileValue)) {
    return Array.from(new Set(fileValue.map((v) => v.trim()).filter((v) => v.length > 0)));
  }
  return Array.from(
    new Set(
      (raw ?? "")
        .split(",")
        .map((value) => value.trim())
        .filter((value) => value.length > 0),
    ),
  );
}

/**
 * Parses a positive integer from an environment variable.
 *
 * @param {string} name - Environment variable name.
 * @param {number} defaultValue - Fallback when absent or invalid.
 * @returns {number}
 */
function parsePositiveInt(name, defaultValue, fileValue) {
  const raw = Deno.env.get(name);
  if (!raw || raw.trim().length === 0) {
    // No env var: fall back to the file, then the built-in default.
    if (Number.isInteger(fileValue) && fileValue >= 1) return fileValue;
    return defaultValue;
  }

  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 1) {
    return defaultValue;
  }

  return parsed;
}

/**
 * Env lookup that treats an EMPTY value as absent.
 *
 * `Deno.env.get("X") ?? fileValue` is wrong: `??` falls through only on
 * null/undefined, so `X=""` yields "" and shadows the file. Empty and unset
 * mean the same thing for configuration, and the rest of this module already
 * treats them alike (see parsePositiveInt).
 */
function envOr(name) {
  const raw = Deno.env.get(name);
  return raw === undefined || raw.trim().length === 0 ? undefined : raw;
}

/**
 * Known TOML tables and the config keys each may set.
 *
 * An allowlist, deliberately. An unrecognised table or key makes loadTomlFile
 * THROW rather than be ignored: a silently-dropped setting in a secrets gate
 * is a config that looks applied and is not.
 */
const TOML_SCHEMA = {
  metadata: { name: "string", version: "string" },
  server: { host: "string", port: "number", health_path: "string", ready_path: "string" },
  secrets: { required: "string[]", sources: "string[]" },
  rate_limit: { window_ms: "number", max: "number", auth_fail_max: "number" },
  policy: { backend: "string", command: "string", command_args: "string", timeout_ms: "number" },
  audit: { enabled: "boolean", path: "string", request_log: "boolean" },
};

/** TOML `table.key` -> the flat config field it populates. */
const TOML_TO_CONFIG = {
  "server.host": "host",
  "server.port": "port",
  "server.health_path": "healthPath",
  "server.ready_path": "readyPath",
  "secrets.required": "requiredSecrets",
  "rate_limit.window_ms": "rateLimitWindowMs",
  "rate_limit.max": "rateLimitMax",
  "rate_limit.auth_fail_max": "rateLimitAuthFailMax",
  "policy.backend": "policyBackend",
  "policy.command": "policyCommand",
  "policy.command_args": "policyCommandArgs",
  "policy.timeout_ms": "policyTimeoutMs",
  "audit.enabled": "auditLogEnabled",
  "audit.path": "auditLogPath",
  "audit.request_log": "requestLogEnabled",
};

function typeOk(value, expected) {
  if (expected === "string") return typeof value === "string";
  if (expected === "number") return typeof value === "number";
  if (expected === "boolean") return typeof value === "boolean";
  if (expected === "string[]") {
    return Array.isArray(value) && value.every((v) => typeof v === "string");
  }
  return false;
}

/**
 * Read and validate a rokur.toml, returning flat config overrides.
 *
 * THROWS on anything it does not fully understand -- unreadable file, TOML
 * syntax error, unknown table, unknown key, wrong type. It never returns a
 * partial result. rokur is a secrets gate: starting with a half-read policy is
 * worse than not starting at all.
 *
 * @param {string} path
 * @returns {object} flat overrides, e.g. { port: 9090, requiredSecrets: [...] }
 */
export function loadTomlFile(path) {
  let text;
  try {
    text = Deno.readTextFileSync(path);
  } catch (err) {
    throw new Error(`rokur: cannot read config file ${path}: ${err.message}`);
  }

  let parsed;
  try {
    parsed = parseToml(text);
  } catch (err) {
    throw new Error(`rokur: ${path} is not valid TOML: ${err.message}`);
  }

  const overrides = {};
  for (const [table, entries] of Object.entries(parsed)) {
    const known = TOML_SCHEMA[table];
    if (!known) {
      throw new Error(
        `rokur: ${path} has unknown table [${table}]. Known: ${Object.keys(TOML_SCHEMA).join(", ")}`,
      );
    }
    if (typeof entries !== "object" || entries === null) {
      throw new Error(`rokur: ${path} table [${table}] is not a table`);
    }
    for (const [key, value] of Object.entries(entries)) {
      // rokur is a secrets gate, NOT a reverse proxy. The bundle's rokur.toml
      // once described `backend` forwarding, which rokur has never
      // implemented; accepting the key would imply otherwise.
      if (table === "server" && key === "backend") {
        throw new Error(
          `rokur: ${path} sets [server] backend. rokur is a secrets gate, not a proxy -- it forwards nothing.`,
        );
      }
      const expected = known[key];
      if (!expected) {
        throw new Error(
          `rokur: ${path} has unknown key [${table}] ${key}. Known: ${Object.keys(known).join(", ")}`,
        );
      }
      if (!typeOk(value, expected)) {
        throw new Error(
          `rokur: ${path} [${table}] ${key} must be ${expected}, got ${typeof value}`,
        );
      }
      const field = TOML_TO_CONFIG[`${table}.${key}`];
      if (field) overrides[field] = value;
    }
  }
  return overrides;
}

/**
 * Loads every Rokur configuration value from the environment.
 *
 * Safe to call multiple times — each invocation re-reads the environment so
 * that SIGHUP-triggered reloads pick up changes.
 *
 * @returns {object} Configuration object.
 */
export function loadConfig(options = {}) {
  //  Precedence is env > file > built-in default, in that order, per the
  //  bundle contract: an operator's environment must always be able to
  //  override a file shipped in an image.
  const fileCfg = options.configPath ? loadTomlFile(options.configPath) : {};

  const host = envOr("ROKUR_HOST") ?? fileCfg.host ?? "127.0.0.1";
  const port = Number(envOr("ROKUR_PORT") ?? fileCfg.port ?? "9090");
  const healthPath = envOr("ROKUR_HEALTH_PATH") ?? fileCfg.healthPath ?? "/health";
  const readyPath = envOr("ROKUR_READY_PATH") ?? fileCfg.readyPath ?? "/ready";
  const apiToken = (Deno.env.get("ROKUR_API_TOKEN") ?? "").trim();
  const requiredSecrets = parseRequiredSecrets(fileCfg.requiredSecrets);
  const env = (Deno.env.get("ROKUR_ENV") ?? "development").trim().toLowerCase();

  const policyBackend = (envOr("ROKUR_POLICY_BACKEND") ?? fileCfg.policyBackend ?? "builtin")
    .trim().toLowerCase();
  const policyCommand = (envOr("ROKUR_POLICY_COMMAND") ?? fileCfg.policyCommand ?? "").trim();
  const policyCommandArgs = (envOr("ROKUR_POLICY_COMMAND_ARGS") ?? fileCfg.policyCommandArgs ?? "")
    .trim();
  const policyTimeoutMs = parsePositiveInt("ROKUR_POLICY_TIMEOUT_MS", 1500, fileCfg.policyTimeoutMs);

  const rateLimitWindowMs = parsePositiveInt("ROKUR_RATE_LIMIT_WINDOW_MS", 60_000, fileCfg.rateLimitWindowMs);
  const rateLimitMax = parsePositiveInt("ROKUR_RATE_LIMIT_MAX", 60, fileCfg.rateLimitMax);
  const rateLimitAuthFailMax = parsePositiveInt("ROKUR_RATE_LIMIT_AUTH_FAIL_MAX", 5, fileCfg.rateLimitAuthFailMax);

  const auditLogEnabled = parseBooleanEnv("ROKUR_AUDIT_LOG", true);
  const auditLogPath = (Deno.env.get("ROKUR_AUDIT_LOG_PATH") ?? "").trim();
  const requestLogEnabled = parseBooleanEnv("ROKUR_REQUEST_LOG", true);

  const allowUnauthenticated = parseBooleanEnv(
    "ROKUR_ALLOW_UNAUTHENTICATED",
    false,
  );
  const allowEmptyRequiredSecrets = parseBooleanEnv(
    "ROKUR_ALLOW_EMPTY_REQUIRED_SECRETS",
    false,
  );

  return {
    host,
    port,
    healthPath,
    readyPath,
    apiToken,
    requiredSecrets,
    env,
    isProduction: env === "production",

    policyBackend,
    policyCommand,
    policyCommandArgs,
    policyTimeoutMs,

    rateLimitWindowMs,
    rateLimitMax,
    rateLimitAuthFailMax,

    auditLogEnabled,
    auditLogPath,
    requestLogEnabled,

    allowUnauthenticated,
    allowEmptyRequiredSecrets,
  };
}

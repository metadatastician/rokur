// SPDX-License-Identifier: MPL-2.0
// Unit tests for Rokur rate limiter.

import { afterEach, beforeEach, describe, expect, it } from "bun:test";
import { createRateLimiter } from "../rate_limit.js";

let limiter;

function cleanRateLimitEnv() {
  for (
    const key of [
      "ROKUR_RATE_LIMIT_WINDOW_MS",
      "ROKUR_RATE_LIMIT_MAX",
      "ROKUR_RATE_LIMIT_AUTH_FAIL_MAX",
    ]
  ) {
    try {
      delete process.env[key];
    } catch { /* noop */ }
  }
}

describe("rate limiter", () => {
  beforeEach(() => {
    cleanRateLimitEnv();
  });

  afterEach(() => {
    if (limiter) {
      limiter.destroy();
      limiter = null;
    }
    cleanRateLimitEnv();
  });

  it("allows requests under the limit", () => {
    process.env["ROKUR_RATE_LIMIT_MAX"] = "5";
    limiter = createRateLimiter();

    for (let i = 0; i < 5; i++) {
      const result = limiter.checkRequest("10.0.0.1");
      expect(result.allowed).toEqual(true);
    }
  });

  it("denies requests over the general limit", () => {
    process.env["ROKUR_RATE_LIMIT_MAX"] = "3";
    limiter = createRateLimiter();

    limiter.checkRequest("10.0.0.1");
    limiter.checkRequest("10.0.0.1");
    limiter.checkRequest("10.0.0.1");
    const result = limiter.checkRequest("10.0.0.1");

    expect(result.allowed).toEqual(false);
    expect(result.reason).toEqual("REQUEST_RATE_EXCEEDED");
  });

  it("tracks IPs independently", () => {
    process.env["ROKUR_RATE_LIMIT_MAX"] = "2";
    limiter = createRateLimiter();

    limiter.checkRequest("10.0.0.1");
    limiter.checkRequest("10.0.0.1");
    const blocked = limiter.checkRequest("10.0.0.1");
    expect(blocked.allowed).toEqual(false);

    // Different IP should still be allowed.
    const different = limiter.checkRequest("10.0.0.2");
    expect(different.allowed).toEqual(true);
  });

  it("denies after auth failure threshold", () => {
    process.env["ROKUR_RATE_LIMIT_AUTH_FAIL_MAX"] = "2";
    process.env["ROKUR_RATE_LIMIT_MAX"] = "100";
    limiter = createRateLimiter();

    limiter.recordAuthFailure("10.0.0.1");
    limiter.recordAuthFailure("10.0.0.1");

    const result = limiter.checkRequest("10.0.0.1");
    expect(result.allowed).toEqual(false);
    expect(result.reason).toEqual("AUTH_FAIL_RATE_EXCEEDED");
  });

  it("auth failures do not affect other IPs", () => {
    process.env["ROKUR_RATE_LIMIT_AUTH_FAIL_MAX"] = "1";
    limiter = createRateLimiter();

    limiter.recordAuthFailure("10.0.0.1");

    const blocked = limiter.checkRequest("10.0.0.1");
    expect(blocked.allowed).toEqual(false);

    const ok = limiter.checkRequest("10.0.0.2");
    expect(ok.allowed).toEqual(true);
  });

  it("reset clears all state", () => {
    process.env["ROKUR_RATE_LIMIT_MAX"] = "1";
    limiter = createRateLimiter();

    limiter.checkRequest("10.0.0.1");
    const blocked = limiter.checkRequest("10.0.0.1");
    expect(blocked.allowed).toEqual(false);

    limiter.reset();

    const afterReset = limiter.checkRequest("10.0.0.1");
    expect(afterReset.allowed).toEqual(true);
  });

  it("stats returns configuration and state", () => {
    process.env["ROKUR_RATE_LIMIT_MAX"] = "42";
    process.env["ROKUR_RATE_LIMIT_AUTH_FAIL_MAX"] = "7";
    process.env["ROKUR_RATE_LIMIT_WINDOW_MS"] = "30000";
    limiter = createRateLimiter();

    limiter.checkRequest("10.0.0.1");
    limiter.checkRequest("10.0.0.2");

    const stats = limiter.stats();
    expect(stats.maxRequests).toEqual(42);
    expect(stats.authFailMax).toEqual(7);
    expect(stats.windowMs).toEqual(30000);
    expect(stats.trackedIps).toEqual(2);
  });

  it("returns positive retryAfterMs when rate limited", () => {
    process.env["ROKUR_RATE_LIMIT_MAX"] = "1";
    limiter = createRateLimiter();

    limiter.checkRequest("10.0.0.1");
    const result = limiter.checkRequest("10.0.0.1");

    expect(result.allowed).toEqual(false);
    expect(result.retryAfterMs > 0).toEqual(true);
  });
});

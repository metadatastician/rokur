<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Rokur — Measured Status

**Last measured:** 2026-07-28  
**Honest completion:** ~70%  
**Languages:** JavaScript (Deno)

> This document records **measured** state: every claim below is a file read, a build
> run, or a test executed on the dates shown. Where an existing document in this repo
> contradicts it, this one is correct and the other is stale. Full evidence and
> cross-repo context: `dev-notes/stapeln-ecosystem-COMPREHENSIVE-SITREP-2026-07-28.md`.

## Summary

~70%. The most complete and most honest component in the ecosystem — and nothing uses it.

## What genuinely works

- 2,302 lines across 10 files. `deno check` clean. **ZERO** TODO, FIXME, stubs, or 'not implemented' throws across 37 functions
- **The only non-vacuous test suite in the ecosystem**: `deno task test` -> 7 tests / 50 steps, all pass. `test/integration_test.js` spins up the REAL HTTP server and exercises it — 401 without token, 400 on invalid JSON, 409 when secrets missing, 404 on unknown path, request-ID propagation
- Per-IP sliding-window rate limiting is real and independently tested
- The documented API matches the code exactly: `/health`, `/v1/secrets/status`, `/v1/authorize-start`, `/metrics`, `/v1/secrets/reload`
- Fail-closed external policy contract implemented in `policy/engine.js`

## What is broken, missing, or misreported

- **Orphaned.** No repo imports or invokes rokur. The only cross-references are in svalinn, in a document describing code that was deleted.
- `ROKUR_GATE_ENABLED` unset is a documented **fail-open** default — the gate does not gate unless explicitly switched on.
- Default config ships `required = []`, so the gate starts open.
- No build or test gate on GitHub — the good tests are not run by CI.
- `LICENSE` claims PMPL-1.0-or-later but ships no PMPL text and points at a nonexistent `../../../LICENSE`.
- No `contractiles/` directory (the only one of the six without) and no ABI-FFI-README.

## Notes and open rulings

- Rokur skipped essentially all the ceremonial scaffolding the other five carry — and it is the only one that fully works. That is a data point about the scaffolding.
- `svalinn/docs/rokur-gate-migration/ROKUR-GATE-CONTRACT.adoc` is a precise behavioural spec written for deleted code. If rokur is wired in, that document is ALREADY the specification.
- OPEN RULING R6: wire rokur in first as the pilot for the bundle contract — cheapest available proof the design works.

## Next actions

1. RULING NEEDED (R6): adopt rokur as the Phase-3 pilot
2. Make rokur read container/stapeln/rokur.toml as its config source
3. Fix the ROKUR_GATE_ENABLED fail-open default to fail closed
4. Add a CI gate that runs the existing (good) test suite
5. Fix LICENSE — claims PMPL but ships no PMPL text

## Ecosystem position

This repo is part of the six-repo container stack designed by `stapeln`. The canonical
integration contract is the 8-file `container/stapeln/` bundle, in which each satellite
consumes its own file:

| File | Consumer |
|---|---|
| `compose.toml` | selur |
| `vordr.toml` | vordr |
| `rokur.toml` | rokur |
| `.gatekeeper.yaml` | svalinn |
| `manifest.toml` + `ct-build.sh` | cerro-torre |
| `deploy.k9.ncl` | K9 / k9-svc |

Runtime chain: `svalinn (443/80) -> rokur (8081) -> app`, with vordr watching all three,
cerro-torre signing each as a `.ctp`, and selur as the network driver.

**As of this measurement no repo emits or consumes that bundle**; five mutually
incompatible ad-hoc contracts exist instead, of which exactly one works.


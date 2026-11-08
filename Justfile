# SPDX-License-Identifier: MPL-2.0
# Justfile — Rokur secrets management gate

# Run the complete Bun test suite.
test:
    bun run test

# Run the development server.
dev:
    bun run dev

# Run the project's reproducible verification task.
check: test

// SPDX-License-Identifier: MPL-2.0
// Example external policy adapter contract for Rokur.
// Replace this with an Ephapax runner invocation when ready.

async function readStdinJson() {
  const text = (await Bun.stdin.text()).trim();
  return text.length > 0 ? JSON.parse(text) : {};
}

function evaluate(payload) {
  const requiredSecrets = Array.isArray(payload.requiredSecrets)
    ? payload.requiredSecrets
    : [];
  const missingSecretCount = 0;
  const allowed = missingSecretCount === 0;

  return {
    allowed,
    policy: allowed ? "allow" : "deny",
    code: allowed ? "AUTHORIZED" : "POLICY_DENIED",
    requiredSecretCount: requiredSecrets.length,
    missingSecretCount,
  };
}

const input = await readStdinJson();
const decision = evaluate(input);
process.stdout.write(JSON.stringify(decision));

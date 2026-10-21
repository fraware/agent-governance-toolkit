/** Node-only conformance against frozen Python-generated Ed25519 receipts. */
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {appraise, actionSha256, canonical, PROFILE_DOMAIN_HEX} from './verify_target_vectors.mjs';
const fixture = JSON.parse(
  readFileSync(new URL('./effect-target-v1-vectors.json', import.meta.url), 'utf8')
);

test('domain, canonical Unicode bytes and SHA-256 match the fixed corpus', () => {
  assert.equal(PROFILE_DOMAIN_HEX, fixture.protocol_domain_hex);
  assert.equal(
    Buffer.from(canonical(fixture.vectors[0].action), 'ascii').toString('hex'),
    fixture.canonical_action_hex,
  );
  assert.equal(actionSha256(fixture.vectors[0].action), fixture.canonical_action_sha256);
});

test('seven independent signature and adversarial verdicts match frozen corpus', () => {
  assert.equal(fixture.vectors.length, 7);
  for (const vector of fixture.vectors) {
    assert.equal(
      appraise({
        action: vector.action, nonce: vector.nonce, receipt: vector.receipt,
        publicKeyHex: fixture.public_key_hex,
        expectedKeySha256: fixture.public_key_sha256,
      }),
      vector.expected, vector.id,
    );
  }
});

test('wrong external pin, malformed claims and a different target fail closed', () => {
  const v = fixture.vectors[0];
  const options = {
    action: v.action, nonce: v.nonce, receipt: v.receipt,
    publicKeyHex: fixture.public_key_hex,
    expectedKeySha256: fixture.public_key_sha256,
  };
  assert.equal(appraise({...options, expectedKeySha256: '0'.repeat(64)}),
               'undetermined');
  assert.equal(appraise({...options, action: {...v.action, value: 5}}),
               'undetermined');
  assert.equal(appraise({...options, action: {...v.action, extra: 'x'}}),
               'undetermined');
  assert.equal(appraise({...options, publicKeyHex: '1'.repeat(64)}),
               'undetermined');
});

test('canonicalization rejects non-integer and ambiguous scalar values', () => {
  assert.throws(() => canonical({n: 1.5}), TypeError);
  assert.throws(() => canonical({n: NaN}), TypeError);
  assert.throws(() => canonical({n: []}), TypeError);
});

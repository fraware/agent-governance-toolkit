# Target-state receipt conformance vectors v1

These vectors are a **research interoperability fixture**, not an industry
standard, trusted deployment, or production identity. The synthetic Ed25519
public key and every receipt signature are intentionally public. No trusted
signing credentials or real customer data are included.

## Scope and canonical bytes

The `effect-target-v1-vectors.json` file contains a pinned raw Ed25519 public
key as hexadecimal, its SHA-256 fingerprint, the exact signature domain,
an example canonical action encoding, its SHA-256 digest, and seven signed or
adversarial observation cases with expected verdicts.

An exact v1 action object contains these six fields, each with a JSON **string**
value.

`action_id`, `subject`, `tenant`, `resource`, `operation`, `value`.

The action ID must be nonempty. Missing/extra keys, non-string field values
and empty action IDs make a claim `undetermined` before signature appraisal.
The signed `action_sha256` value must be 64 lowercase hexadecimal digits.

The research canonicalization is the byte sequence produced by Python

```python
json.dumps(value, sort_keys=True, separators=(",", ":"),
           ensure_ascii=True, allow_nan=False).encode("ascii")
```

For these six fixed ASCII field names, the order is `action_id`,
`operation`, `resource`, `subject`, `tenant`, `value`. Strings
must be preserved without Unicode normalization. Non-ASCII characters are
ASCII-escaped, including `café` encoded with `\\u00e9` in the test vector.
This encoding is **not RFC 8785/JCS**. An adapter must reproduce the pinned
bytes, including escaping conventions, to compare the same action digest.
This is a versioned test profile, not a general-purpose canonicalization
scheme for arbitrary JSON values.

An observation signature verifies the Ed25519 message

```text
ASCII("ACS-EFFECT-TARGET-OBSERVATION-v1") || 0x00 || canonical(payload)
```

The signed payload has exactly seven keys `version` (integer 1),
`kind` (`target_state_snapshot`), `nonce` (string), `action_id` (string),
`state` (`committed` or `absent`), `action_sha256` (digest or JSON null
for absent state) and `observed_at` (nonnegative integer seconds).
The signature is base64 encoded in the receipt envelope, and the verifier
must use the externally authenticated public key.

## Expected results

| Case | Expected verdict |
| --- | --- |
| `exact-commit` | `established` |
| `absent-snapshot` | `refuted` |
| `different-committed-digest` | `refuted` |
| `tampered-signature` | `undetermined` |
| `wrong-signer` | `undetermined` |
| `wrong-expected-nonce` | `undetermined` |
| `different-action-content` | `refuted` |

The sample `observed_at` is historical by design. The verifier does **not**
infer freshness from this timestamp or provide any wall-clock guarantee.
The nonce must originate from an independent requester, and its uniqueness
and retention are caller obligations.

`refuted` is restricted to the exact claim about **one sampled target
state**, not proof of permanent non-execution or absence of an effect elsewhere.

## Verification

With `cryptography` installed, from `policy-engine/` run

```bash
python -m unittest discover -s research -p 'test_effect_target_vectors.py' -v
python -m unittest discover -s research -p 'test_effect_target_protocol.py' -v
python -m unittest discover -s research -p 'test_verify_target_observation.py' -v
```

A new adapter may load the machine-readable vector file, verify signatures
against `public_key_hex`, recompute `canonical_action_sha256` from the
`canonical_action_hex` bytes, and check all expected judgments independently
of the Python reference code.

Successful conformance demonstrates agreement on the frozen fixture.
It does not authenticate the test-vector key as the identity of a real target,
establish that a real target observed all execution paths, or certify the
policy engine that issued an authorization.

# Offline verification of a signed target-state snapshot

This research utility appraises a narrow claim about a committed action using
a target-signed state snapshot. It runs without the ACS SDK, a live agent,
access to the target database, or a connection to the issuing host.

## Inputs and invocation

The verifier receives four independently supplied artifacts and expectations.

- `action.json` contains the exact proposed action with the same field names
  and values that the target hashed. Its `action_id` is mandatory.
- `observation.json` contains the target's signed
  `target_state_snapshot` receipt. It is treated as untrusted input.
- `target-public.raw` contains exactly 32 raw Ed25519 public-key bytes.
- `EXPECTED_KEY_SHA256` is a 64-character lowercase SHA-256 digest of those
  **raw public-key bytes**, authenticated out of band by the verifier's
  operator. The utility never learns a trust anchor from a receipt or target
  bootstrap message. `EXPECTED_NONCE` is the verifier's request challenge,
  independently remembered from the observation request.

From `policy-engine/`, after installing `cryptography` in the environment:

```bash
python research/verify_target_observation.py \
  --action action.json \
  --observation observation.json \
  --target-public-key target-public.raw \
  --expected-key-sha256 "$EXPECTED_KEY_SHA256" \
  --nonce "$EXPECTED_NONCE" \
  --expect established
```

The CLI emits one JSON object with a stable versioned schema, the evidence
verdict, a coarse reason, the claim scope and whether the file matched the
explicitly supplied key fingerprint. It exits zero **only** when the verdict
matches the required `--expect` value. A mismatch exits with code 1. Invalid
command-line arguments exit nonzero under `argparse`.

The CLI's three verdicts have deliberately narrow meanings.

| Verdict | Meaning |
| --- | --- |
| `established` | A valid signature from the externally pinned target key attests that the exact action's digest was present in the target's sampled state |
| `refuted` | A valid pinned-key target snapshot attests absence of that action ID or a different committed digest in that target state at the sampled instant |
| `undetermined` | Incomplete, malformed, untrusted, improperly pinned or mismatched evidence prevents a supported target-state conclusion |

A signed absence is **not** evidence that the action never executed elsewhere,
that it never occurred before the snapshot, or that a transient external
effect was rolled back. The snapshot is a statement about one target's sampled
persistent state. The fingerprint comparison proves agreement with a
*supplied* expected key, not the independent trustworthiness of whoever
supplied that expectation.

## Reproducible test commands

```bash
python -m unittest discover -s research -p 'test_effect_target_protocol.py' -v
python -m unittest discover -s research -p 'test_verify_target_observation.py' -v
```

The first suite verifies the signature/nonce/effect appraisal protocol. The
second generates temporary test keys, receipt and action artifacts and
exercises the offline CLI, mismatched trust anchors, tampered receipts,
malformed input, oversized input, duplicate JSON object keys in either input, failed nonce checks and expectation-driven
exit behavior. The mandatory native ACS workflow runs these independent suites
and subsequently tests actual signed commits under the process and Linux UID
research models.

## Claim boundary and next external experiment

The fixture uses a deterministic JSON encoding based on Python `json.dumps`
with sorted keys, ASCII escaping and no NaN. It is **not** RFC 8785 JSON
Canonicalization Scheme and must be explicitly matched by a cross-language
adapter. The receipt's `observed_at` field is signed, while trusted clock
synchronization, freshness policies and snapshot observation completeness
remain outside this verifier's guarantee.

A genuinely independent administration experiment needs a target whose signing
key, access controls and state storage are controlled by a distinct trusted
administrator. The verifying principal must obtain and pin the target public
key through an authenticated channel independent of the host under test. That
cannot be demonstrated by constructing multiple processes under one CI
administrator, passing a self-declared key fingerprint, or reading the
target's public key from the same untrusted response as the receipt.

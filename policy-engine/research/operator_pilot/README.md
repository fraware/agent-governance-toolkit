# Operator-controlled target-state observation pilot

This package prepares one **offline, separately administered experiment** for
a future external target operator. It does not itself conduct that external
experiment. The existing native ACS protected target accepts signed issuer,
decision and workload credentials and records its committed effects in SQLite.
This pilot adds a minimal observation signer intended to be run by the person
who administers that SQLite target **outside the agent operator's account**.

The protocol is deliberately file-based. It needs no public endpoint, no
shared cloud subscription, no new account access and no secret delivered to
the agent host. It uses the existing `effect_target_protocol.py` v1 receipt
schema and `verify_target_observation.py` offline verifier.

## Roles and administrative ownership

| Role | Exclusive responsibilities | Explicit exclusion |
| --- | --- | --- |
| A, agent/issuer operator | Construct a legitimate or adversarial action request and maintain native ACS decision and grant signers | Must not access B's DB, observation secret, deployment controls or filesystem |
| B, target operator | Provision the target, pin allowed issuer and policy public keys, control target DB and observation signer, execute commit and observation | Must not share observation private key or target storage authority with A |
| V, independent verifier | Choose and retain a fresh nonce, authenticate B's target public-key fingerprint through a separate trusted channel, receive action and receipt, appraise | Must not accept the trust anchor supplied solely in A's or the receipt's untrusted channel |

The current CI harness has only one administrative operator and accordingly
does **not** satisfy these separation requirements.

## Target operator B setup

Install Python 3.12+ and `cryptography`. The target operator must keep the
target SQLite database and private signing key in directories controlled
exclusively by B. Run from `policy-engine/` under B's unprivileged Unix UID.

```bash
umask 077
mkdir -m 700 -p /path/controlled-by-B/target-keys
python research/operator_pilot/target_observer.py init \
  --key-dir /path/controlled-by-B/target-keys
```

This creates `observation-private.raw` and `observation-public.raw` once,
both with mode `0600`, and prints the SHA-256 fingerprint of the raw public
key. The CLI refuses key regeneration over existing files. At each observation,
the target also rechecks that the private key's directory is owned by its
operating UID and inaccessible to other UIDs. A protected file under an
externally writable directory is not sufficient. The operator
communicates the 32-byte **public** key to V and independently authenticates
its printed 64-character lowercase fingerprint. **The observation private key
and SQLite database never leave B's control.**

B's protected target is responsible for creating and maintaining a SQLite DB
with a table named `effects`. Its `action_id` is a primary key and its
`action_bytes` is the canonical JSON-encoded v1 action. The existing native
research `TwoKeyTarget` uses precisely this schema. The pilot observer
checks canonical stored bytes, refuses malformed data and reads state without
creating or modifying the target database. Duplicate matching records are
bounded to two rows and rejected, and the read-only SQLite connection is
explicitly closed. The containing directory must be
owned by B with mode `0700`; the database file must be B-owned and mode
`0600`. A passing file-mode test alone does not demonstrate a denial across
different UIDs; the separate Linux UID CI test covers the stated OS-principal
access restrictions for its own test environment. Validate these permissions
and separately document how the target
enforces *all* writable paths.

## Requester challenge and target response

V chooses a cryptographically unpredictable 16-byte random value as 32
lowercase hex characters, records it locally, and sends this exact JSON
object to B through an approved channel.

```json
{
  "schema": "effect-target-challenge/v1",
  "action_id": "record-001",
  "nonce": "0123456789abcdef0123456789abcdef"
}
```

The nonce above is **illustrative only** and must not be reused in a real run.
Use `python -c 'import secrets; print(secrets.token_hex(16))'` for a new nonce.

B writes the request as a bounded UTF-8 JSON file `challenge.json`,
confirms its `action_id` is the requested target artifact, and signs the
result of a read-only SQLite snapshot.

```bash
python research/operator_pilot/target_observer.py observe \
  --database /path/controlled-by-B/state/ledger.sqlite \
  --challenge challenge.json \
  --secret-key /path/controlled-by-B/target-keys/observation-private.raw \
  > observation.json
```

The output is a signed JSON receipt with `committed` or `absent` state for
one target's sampled persistent database. An incorrect or incomplete challenge,
foreign-owned/permission-exposed database, unprotected signing key, corrupt
committed bytes or missing database produces an error **without a signed
receipt**. The wall-clock `observed_at` is advisory, not authenticated time.

## Offline verification by V

V independently receives `action.json` describing the **exact original
action**, `observation.json`, B's 32-byte public-key file and B's separately
authenticated fingerprint. V uses the fresh challenge nonce it retained.

```bash
python research/verify_target_observation.py \
  --action action.json \
  --observation observation.json \
  --target-public-key target-public.raw \
  --expected-key-sha256 "$PIN_AUTHENTICATED_FROM_B" \
  --nonce "$VERIFIER_ORIGINATED_NONCE" \
  --expect established
```

A valid target signature and exact match produces `established` for the
sampled state; a valid snapshot with absent/different action content produces
`refuted`; uncertain/missing/invalid evidence produces `undetermined`.
The command exits nonzero if the result disagrees with `--expect`.

**A correctly signed absence does not prove the action never executed**, and
a matching signed snapshot does not establish global effect-path completeness.
A second administrative domain must be verified from operating credentials,
state custody and external adjudicator notes, not inferred from the signatures.

## Frozen protocol and required experimental record

Before actual external execution, freeze the exact commits, software versions,
hashes of allowed policies, enrolled issuer/decision/identity public keys,
target observation key fingerprint, target storage owner and access policy,
and a named operator/adjudicator. Obtain *consent and cost authorization*
for any target deployment.

For each of the following predefined cases, independently record the actual
target-side truth and the three-valued verifier judgment. Keep legitimate
commit, unsigned bypass, wrong action arguments, replay, rejected grant,
post-tool denial after commit, host-reported success without commit and
unavailable or untrusted signed observation as distinct conditions. Verify
that the adjudicator never treats a missing receipt as proof of nonexecution.

Measure false established claims, correct refusals, inconclusive rates,
legitimate completion and overhead against a declared denominator. Publish
test records with code SHAs, exact command lines and redacted signed
non-sensitive evidence. **Do not invent independent operator identities,
trial counts, timing results, outcomes or a separate trust domain.**

## Local smoke test versus external completion

```bash
PYTHONPATH=research python -m unittest discover \
  -s research/operator_pilot -p 'test_target_observer.py' -v
```

This runs deterministic, local functional/adversarial checks with synthetic
keys and SQLite records. Passing these tests establishes parser, permission,
signature and appraisal behavior only. The experiment is **externally
completed** only after distinct operators perform the actual target commit,
sign target-owned state and have a separate verifier independently adjudicate
the result.

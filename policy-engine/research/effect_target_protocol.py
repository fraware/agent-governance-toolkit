"""Experimental signed target-state observations, independent of ACS APIs.

A trusted target signs a snapshot assertion about its own database. A verifier
pinned to the target's public key classifies that exact claim as established,
refuted, or undetermined. This code does not establish independent key custody,
completeness across other execution paths, or permanent absence of effects.
"""
from __future__ import annotations

import base64
import binascii
from hashlib import sha256
import json
import time

from cryptography.exceptions import InvalidSignature

OBSERVATION_DOMAIN = b"ACS-EFFECT-TARGET-OBSERVATION-v1\0"
ACTION_FIELDS = frozenset({
    "action_id", "subject", "tenant", "resource", "operation", "value",
})
OBSERVATION_FIELDS = frozenset({
    "version", "kind", "nonce", "action_id", "state", "action_sha256",
    "observed_at",
})


def canonical(value):
    """Fixture-specific deterministic JSON; not a general JCS implementation."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def valid_action(action):
    """Version-one target action schema; strings only for portable encoding."""
    return (
        type(action) is dict
        and set(action) == ACTION_FIELDS
        and all(type(value) is str for value in action.values())
        and bool(action["action_id"])
    )


def valid_digest(digest):
    return (type(digest) is str and len(digest) == 64
            and all(ch in "0123456789abcdef" for ch in digest))


def action_sha256(action):
    if not valid_action(action):
        raise ValueError("unsupported target action schema")
    return sha256(canonical(action)).hexdigest()


def signed_observation(private_key, *, action_id, nonce, state,
                       action_digest=None, observed_at=None):
    """Issue a target-signed snapshot after reading authoritative state."""
    if type(action_id) is not str or not action_id:
        raise ValueError("nonempty action_id required")
    if type(nonce) is not str or not nonce:
        raise ValueError("nonempty nonce required")
    if state not in ("committed", "absent"):
        raise ValueError("invalid target snapshot state")
    if state == "committed":
        if not valid_digest(action_digest):
            raise ValueError("committed observation requires action digest")
    elif action_digest is not None:
        raise ValueError("absent snapshot must not claim an action digest")
    if type(observed_at) is not int and observed_at is not None:
        raise ValueError("observed_at must be integer seconds")
    if observed_at is not None and observed_at < 0:
        raise ValueError("negative observation time")
    payload = {
        "version": 1, "kind": "target_state_snapshot",
        "nonce": nonce, "action_id": action_id, "state": state,
        "action_sha256": action_digest,
        "observed_at": int(time.time()) if observed_at is None else observed_at,
    }
    signature = private_key.sign(OBSERVATION_DOMAIN + canonical(payload))
    return {
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def appraise_observation(receipt, pinned_public_key, *, action, nonce):
    """Classify the claimed commit at the observed target's snapshot instant.

    'refuted' means the signed target snapshot is inconsistent with *this*
    claimed commit at that instant. It does not assert that no effect occurred
    outside this target, before the snapshot, or via another state path.
    'undetermined' is mandatory on missing, invalid, or untrusted evidence.
    """
    try:
        if (type(receipt) is not dict
                or set(receipt) != {"payload", "signature"}):
            return "undetermined"
        payload = receipt["payload"]
        if type(payload) is not dict or set(payload) != OBSERVATION_FIELDS:
            return "undetermined"
        if (not valid_action(action)
                or type(nonce) is not str or not nonce):
            return "undetermined"
        if (type(payload["version"]) is not int
                or payload["version"] != 1
                or type(payload["kind"]) is not str
                or payload["kind"] != "target_state_snapshot"
                or type(payload["nonce"]) is not str
                or payload["nonce"] != nonce
                or type(payload["action_id"]) is not str
                or payload["action_id"] != action["action_id"]
                or type(payload["observed_at"]) is not int
                or payload["observed_at"] < 0
                or type(payload["state"]) is not str
                or payload["state"] not in ("committed", "absent")):
            return "undetermined"
        state = payload["state"]
        digest = payload["action_sha256"]
        if (state == "absent" and digest is not None) or (
            state == "committed"
            and not valid_digest(digest)
        ):
            return "undetermined"
        signature = base64.b64decode(receipt["signature"], validate=True)
        pinned_public_key.verify(
            signature, OBSERVATION_DOMAIN + canonical(payload),
        )
        if state == "absent":
            return "refuted"
        return (
            "established" if digest == action_sha256(action) else "refuted"
        )
    except (InvalidSignature, ValueError, TypeError, KeyError, OverflowError,
            AttributeError, binascii.Error):
        return "undetermined"

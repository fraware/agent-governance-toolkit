"""Operator-held target-state snapshot signer for a *separate-admin* pilot.

Runs on the TARGET operator's host. No ACS SDK, agent host, or network needed.
The caller supplies a challenge; only the target owner can read local SQLite
state and the persistent Ed25519 observation key. This does not itself prove
who administers the host, provide complete mediation, or authenticate the
operator's public-key distribution channel. It MUST NOT run on the agent host
when claiming an external administrative boundary.
"""
from __future__ import annotations

import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from effect_target_protocol import action_sha256, canonical, signed_observation, valid_action  # noqa: E402


class PilotInputError(ValueError):
    """Invalid operator input or unsafe local state; terminate without receipt."""


def restricted_file(path: Path, *, require_directory: bool = False) -> None:
    """Reject symlinks, foreign ownership and any group/other permission bits."""
    metadata = path.lstat()
    kind_ok = stat.S_ISDIR(metadata.st_mode) if require_directory else stat.S_ISREG(metadata.st_mode)
    if (not kind_ok or metadata.st_uid != os.geteuid()
            or (stat.S_IMODE(metadata.st_mode) & 0o077)):
        raise PilotInputError(f"incorrect target-owned permissions for {path}")


def read_limited(path: Path, maximum: int) -> bytes:
    with path.open("rb") as handle:
        contents = handle.read(maximum + 1)
    if len(contents) > maximum:
        raise PilotInputError("oversized input")
    return contents


def unique_pairs(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise PilotInputError("duplicate JSON field")
        output[key] = value
    return output


def read_challenge(path: Path):
    try:
        request = json.loads(read_limited(path, 4096).decode("utf-8"),
                             object_pairs_hook=unique_pairs)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PilotInputError("invalid challenge") from exc
    if (type(request) is not dict
            or set(request) != {"schema", "action_id", "nonce"}
            or request["schema"] != "effect-target-challenge/v1"
            or type(request["action_id"]) is not str or not request["action_id"]
            or type(request["nonce"]) is not str or len(request["nonce"]) < 32
            or len(request["nonce"]) > 128
            or any(ch not in "0123456789abcdef" for ch in request["nonce"])):
        raise PilotInputError("unsupported challenge or weak nonce")
    return request


def write_new(path: Path, raw: bytes):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    handle = os.open(path, flags, 0o600)
    try:
        with os.fdopen(handle, "wb") as output:
            output.write(raw)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def initialize_operator_key(directory: Path):
    """Create private and public keys once, without exposing a private key."""
    restricted_file(directory, require_directory=True)
    private_file = directory / "observation-private.raw"
    public_file = directory / "observation-public.raw"
    if private_file.exists() or public_file.exists():
        raise PilotInputError("refusing to overwrite an existing key pair")
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    write_new(private_file, private)
    try:
        write_new(public_file, public)
    except BaseException:
        private_file.unlink(missing_ok=True)
        raise
    return {"public_key_sha256": hashlib.sha256(public).hexdigest(),
            "public_key_file": str(public_file)}


def read_private_key(path: Path):
    restricted_file(path)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    handle = os.open(path, flags)
    with os.fdopen(handle, "rb") as private_file:
        metadata = os.fstat(private_file.fileno())
        if (not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) & 0o077):
            raise PilotInputError("unprotected signing key")
        raw = private_file.read(33)
    if len(raw) != 32:
        raise PilotInputError("invalid private key length")
    return Ed25519PrivateKey.from_private_bytes(raw)


def snapshot(db_file: Path, challenge_file: Path, key_file: Path):
    """Read one committed SQLite target state and sign a bounded observation."""
    request = read_challenge(challenge_file)
    restricted_file(db_file)
    restricted_file(db_file.parent, require_directory=True)
    key = read_private_key(key_file)
    # Existing native target's effects table stores canonical action bytes.
    # A separate read transaction observes only this target-owned database.
    with closing(sqlite3.connect(db_file.resolve().as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("BEGIN")
        rows = db.execute(
            "SELECT action_bytes FROM effects WHERE action_id=? LIMIT 2",
            (request["action_id"],),
        ).fetchall()
        if len(rows) > 1:
            raise PilotInputError("ambiguous target effect rows")
        if rows:
            raw = rows[0][0]
            if type(raw) is not bytes or len(raw) > 1024 * 1024:
                raise PilotInputError("invalid stored action bytes")
            try:
                action = json.loads(raw.decode("ascii"), object_pairs_hook=unique_pairs)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise PilotInputError("corrupt stored action") from exc
            if (not valid_action(action)
                    or action["action_id"] != request["action_id"]
                    or canonical(action) != raw):
                raise PilotInputError("stored action does not match target identity")
            digest = action_sha256(action)
        else:
            digest = None
        db.commit()
    # Timestamp is the signer's wall clock, not the instantaneous database
    # read time and not an independently authenticated timestamp.
    return signed_observation(
        key, action_id=request["action_id"], nonce=request["nonce"],
        state="committed" if digest is not None else "absent",
        action_digest=digest, observed_at=int(time.time()),
    )


def main(argv=None):
    if os.name != "posix" or not hasattr(os, "geteuid"):
        raise PilotInputError("POSIX permissions required")
    parser = argparse.ArgumentParser(description="Target-operator pilot snapshot signer")
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init", help="Generate target-held signing key pair")
    init.add_argument("--key-dir", type=Path, required=True)
    observe = commands.add_parser("observe", help="Sign target-owned state for requester nonce")
    observe.add_argument("--database", type=Path, required=True)
    observe.add_argument("--challenge", type=Path, required=True)
    observe.add_argument("--secret-key", type=Path, required=True)
    args = parser.parse_args(argv)
    response = (initialize_operator_key(args.key_dir) if args.command == "init"
                else snapshot(args.database, args.challenge, args.secret_key))
    print(json.dumps(response, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (PilotInputError, OSError, sqlite3.DatabaseError, ValueError) as exc:
        print(f"TARGET_OPERATOR_ERROR: {type(exc).__name__}", file=sys.stderr)
        sys.exit(2)

"""Linux-only CI evidence for a separate target operating-system principal.

The privileged test supervisor provisions *both* UIDs and all signing identities.
It has root authority and could bypass these controls; the experiment establishes
only protection against an agent-host process running as an unprivileged, distinct
UID. It does not establish a separate administrative organization, remote target,
network isolation, trusted clock, or global complete mediation.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import pwd
import select
import socket
import subprocess
import sys
import tempfile
import time
from uuid import uuid4

if sys.platform != "linux":
    raise SystemExit("LINUX_UID_GATE_UNAVAILABLE: Linux required")

TEST_DIR = Path(__file__).resolve().parents[1] / "sdk" / "python" / "tests"
RESEARCH_DIR = Path(__file__).resolve().parents[1] / "research"
sys.path.insert(0, str(TEST_DIR))
sys.path.insert(0, str(RESEARCH_DIR))

# These synthetic identities are reserved for a disposable, single-use CI VM.
TARGET_UID = 62031
HOST_UID = 62032


def drop_identity(uid):
    """Drop supplementary groups, primary group, and root credentials."""
    os.setgroups([])
    os.setgid(uid)
    os.setuid(uid)
    os.umask(0o077)


def socket_json(sock, payload):
    sock.sendall(json.dumps(payload, separators=(",", ":")).encode("utf-8") + b"\n")
    return read_json_line(sock)


def read_json_line(sock):
    collected = bytearray()
    deadline = time.monotonic() + 12
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([sock], [], [], remaining)[0]:
            raise TimeoutError("target IPC response timed out")
        chunk = sock.recv(1)
        if not chunk:
            raise RuntimeError("target closed IPC")
        if chunk == b"\n":
            return json.loads(collected.decode("utf-8"))
        collected.extend(chunk)
        if len(collected) > 262144:
            raise RuntimeError("oversized target IPC response")


def host_client(fd, db_path, target_pid):
    """Simulated unprivileged agent host with access only to the target IPC."""
    probes = {}
    for name, path, flags in (
        ("read_denied", db_path, os.O_RDONLY),
        ("write_denied", db_path, os.O_WRONLY),
        ("target_memory_denied", f"/proc/{target_pid}/mem", os.O_RDONLY),
    ):
        try:
            descriptor = os.open(path, flags)
        except PermissionError:
            probes[name] = True
        else:
            os.close(descriptor)
            probes[name] = False
        # Other error classes invalidate this narrowly specified experiment.
    request = json.loads(sys.stdin.read())
    with socket.socket(fileno=fd) as conn:
        reply = socket_json(conn, request)
    print(json.dumps({
        "uid": os.geteuid(), "probes": probes, "reply": reply,
    }), flush=True)


def main():
    if os.geteuid() != 0:
        raise RuntimeError("LINUX_UID_GATE_UNAVAILABLE: privileged CI supervisor required")
    for uid in (TARGET_UID, HOST_UID):
        try:
            pwd.getpwuid(uid)
        except KeyError:
            pass
        else:
            raise RuntimeError(f"reserved synthetic UID already exists: {uid}")

    # Native signer uses compiled ACS with three test-provisioned signing roots.
    from cryptography.hazmat.primitives import serialization
    from test_effect_grounded_native_signed_target import Action
    import test_effect_grounded_native_provisioned_identity as native_fixture
    from test_effect_grounded_native_dual_attestation import encode
    from effect_target_protocol import appraise_observation

    fixture = native_fixture.NativeProvisionedWorkloadTests(
        methodName="test_three_valid_signatures_commit_one_effect",
    )
    fixture.setUp()
    target = None
    local_sock = None
    try:
        with tempfile.TemporaryDirectory(prefix="acs-target-uid-") as root_dir:
            # The host UID lacks search permission on the directory and cannot
            # access the SQLite database through the filesystem.
            os.chown(root_dir, TARGET_UID, TARGET_UID)
            os.chmod(root_dir, 0o700)
            db_path = str(Path(root_dir) / "protected.sqlite3")

            def encode_key(key):
                return encode(key.public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw,
                ))

            local_sock, remote_sock = socket.socketpair(socket.AF_UNIX)
            target_script = str(TEST_DIR / "test_effect_grounded_native_target_service.py")
            try:
                target = subprocess.Popen(
                    [
                        sys.executable, "-u", target_script, "--target-server", db_path,
                        encode_key(fixture.issuer.public),
                        encode_key(fixture.policy_public),
                        encode_key(fixture.identity.public),
                    ],
                    stdin=remote_sock.fileno(), stdout=remote_sock.fileno(),
                    stderr=subprocess.PIPE, close_fds=True,
                    preexec_fn=lambda: drop_identity(TARGET_UID),
                )
            finally:
                remote_sock.close()

            hello = read_json_line(local_sock)
            if (set(hello) != {"ready", "observation_public_key"}
                    or hello["ready"] is not True):
                raise AssertionError("unexpected target bootstrap")
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            from test_effect_grounded_native_dual_attestation import decode
            target_key = Ed25519PublicKey.from_public_bytes(
                decode(hello["observation_public_key"]),
            )
            if Path(db_path).stat().st_uid != TARGET_UID:
                raise AssertionError("target SQLite store has wrong operating principal")
            if Path(db_path).stat().st_mode & 0o077:
                raise AssertionError("target SQLite permissions accessible to other UIDs")

            action = fixture.action
            identity = fixture.identity.issue(action)
            proof = fixture.evaluate(action, identity)
            issuer_grant = fixture.issuer.sign(action)
            authorization = {
                "op": "commit", "action": action.args(),
                "identity": identity, "proof": proof,
                "grant": {
                    "payload": issuer_grant["payload"],
                    "signature": encode(issuer_grant["signature"]),
                },
            }

            def from_host(request):
                child = subprocess.Popen(
                    [
                        sys.executable, str(Path(__file__).resolve()), "--host-client",
                        str(local_sock.fileno()), db_path, str(target.pid),
                    ],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, close_fds=True,
                    pass_fds=(local_sock.fileno(),),
                    preexec_fn=lambda: drop_identity(HOST_UID),
                )
                stdout, stderr = child.communicate(
                    input=json.dumps(request), timeout=20,
                )
                if child.returncode:
                    raise RuntimeError(f"unprivileged client failed: {stderr[-300:]}")
                result = json.loads(stdout)
                if result["uid"] != HOST_UID or not all(result["probes"].values()):
                    raise AssertionError("unprivileged host bypassed target boundaries")
                return result["reply"]

            def observe(action_obj):
                nonce = uuid4().hex
                receipt = socket_json(local_sock, {
                    "op": "observe", "action_id": action_obj.action_id,
                    "nonce": nonce,
                })
                return appraise_observation(
                    receipt, target_key, action=action_obj.args(), nonce=nonce,
                )

            # Direct agent-host calls without a signed authorization fail.
            direct = {
                "op": "commit", "action": action.args(), "grant": {},
                "proof": {}, "identity": {},
            }
            if from_host(direct) != {"error": "PermissionError"}:
                raise AssertionError("target accepted unsigned unprivileged bypass")
            if observe(action) != "refuted":
                raise AssertionError("signed absence snapshot did not refute commit")

            if from_host(authorization) != {"result": "committed"}:
                raise AssertionError("authorized signed host request failed")
            if observe(action) != "established":
                raise AssertionError("signed target evidence did not establish commit")

            if from_host(authorization) != {"result": "already_committed"}:
                raise AssertionError("same authorized request was not idempotent")

            mutated = dict(authorization)
            changed = Action(
                action.action_id, action.subject, action.tenant,
                "/granted/other", action.value,
            )
            mutated["action"] = changed.args()
            if from_host(mutated) != {"error": "PermissionError"}:
                raise AssertionError("target accepted changed unprivileged request")
            if observe(action) != "established":
                raise AssertionError("rejected mutation affected original commit")
            if observe(changed) != "refuted":
                raise AssertionError("target-signed snapshot did not refute changed action")

            print(
                "LINUX_UID_TARGET_PASSED: host and target run under distinct "
                "unprivileged UIDs; direct DB read/write and target-memory access "
                "denied; unsigned bypass rejected; native signed commit, replay, "
                "mutation rejection and signed target observations verified",
                flush=True,
            )
    finally:
        if local_sock is not None:
            local_sock.close()
        if target is not None:
            try:
                target.wait(timeout=5)
            except subprocess.TimeoutExpired:
                target.terminate()
                target.wait(timeout=5)
            if target.stderr is not None:
                target.stderr.close()
        fixture.doCleanups()


if __name__ == "__main__":
    if len(sys.argv) == 5 and sys.argv[1] == "--host-client":
        host_client(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    elif len(sys.argv) == 1:
        main()
    else:
        raise SystemExit("usage: run as privileged CI supervisor or --host-client fd db pid")

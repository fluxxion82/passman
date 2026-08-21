# Passman

A local-only password manager for Android and Desktop, built with Kotlin Multiplatform and Compose Multiplatform.

There is no cloud, no account server, and no telemetry. Vaults live on your devices, and two devices you own sync directly over your LAN — mutually authenticated TLS on the wire, post-quantum hybrid encryption on the payload.

> **Status: alpha.** The cryptographic design is documented in detail, but the code has not had an independent security audit. Use accordingly.

## Highlights

- **Local-only by design.** No server to breach, no account to phish, nothing leaves your network.
- **One memory-hard gate.** The login password goes through Argon2id (64 MiB, t=3) to unwrap a device keyring; every other secret derives from a random 32-byte Device Master Key via HKDF. A copied vault file cannot be password-ground on its own — an attacker must break the keyring first.
- **Post-quantum sync.** On upgraded pairings, payloads are sealed with X25519 + ML-KEM-768 (hybrid AND-construction) and signed with ML-DSA-65. Harvest-now-decrypt-later against recorded sync traffic is covered.
- **Explicit pairing ceremony.** Devices pair by comparing a 25-digit safety number rendered on both screens — no trust-on-first-use. Nothing is persisted until both sides confirm a match.
- **Compose Multiplatform UI** shared between Android and Desktop; an iOS port is planned.

## How syncing works

Sync is manual, mutual, and local. Two paired devices exchange one artifact at a time — passwords, PGP keys, or keystores — directly over your LAN. There is no background sync, no relay, and nothing listens when you are not actively syncing.

### One-time setup: pairing

1. On **both** devices, open **Settings → Trusted Devices** and add the other device by its LAN IP address. There is no automatic discovery — you type the address (a DHCP reservation or static IP for both devices saves grief later).
2. Both screens show the same **25-digit safety number** (five groups of five). Compare them by eye and confirm only if they match. Nothing is persisted until you confirm; cancelling leaves no record.
3. While pairing, each device picks what the other is allowed to sync — passwords, PGP keys, keystores — via per-device checkboxes. These are enforced on every request, not just in the UI.

The peer's address is fixed at pairing time. If a device's IP changes later (DHCP renewal, new router), sync fails with "host not paired" — re-run the pairing ceremony with the **same device name**, and the address is updated while the underlying trust (the pinned certificate) carries over.

### Syncing

The Passwords, PGP Keys, and Keystores screens each have a sync icon in the top bar, and each syncs only its own artifact.

1. Tap sync on device A. A banner with a 60-second countdown (and a cancel button) appears — the device is now waiting for its peer.
2. Tap the same sync icon on device B within that minute.
3. Both devices push, then pull and merge. Keep both apps open until the banners clear. If the peer never taps, you get "Peer did not enter sync mode" and can retry or change the address.

Transfers are whole-artifact — the full password vault, or complete key bundles — not deltas. Both devices must run the same app version.

### What gets synced — and what never is

- **Passwords** — every vault entry, merged (see conflicts below).
- **PGP keys** — public *and secret* keyrings, matched by filename.
- **Keystores** — keystore files, matched by filename.

Device identity and recovery material is **never** synced, in either direction: `<user>.pfx` (and its `.bak` / `.lock` siblings), `keyring.pmk` / `keyring.pmk.next`, `hybrid.key`, `mldsa.key`, `portable-recovery.pmk` / `.previous`, and `<user>.recovery.p12` / `.crt`. Each device generates its own. The consequence is worth stating plainly: **a second device is not a backup.** It replicates your entries, but not the keys that unlock them on this device — back up the whole `keystore/<user>/` directory yourself.

Because keys and keystores match by filename, give the files you create names you would not pick twice. Two devices that independently create a keystore called `work.pfx` are creating *different* files under one name, and the first sync between them overwrites one with the other — for a PGP secret ring that is key material gone. Nothing is created behind your back to trip over this: a new profile starts with no keys and no keystores, you make what you need on the Create screens, and a second device inherits them by syncing rather than by minting its own.

### On the wire

For the technically curious: sync data moves over mutual TLS on port 2323 — client certificates required, TLS 1.3 preferred with 1.2 permitted, both ends pinned to the exact certificates (SPKI) exchanged at pairing. Inside that channel, payloads are additionally sealed to public keys pinned during the ceremony: X25519 + ML-KEM-768 hybrid encryption, plus an ML-DSA-65 signature on upgraded pairings. Pairings made before the post-quantum upgrade still use classical RSA-OAEP + AES-GCM sealing until the ceremony is re-run from the Trusted Devices screen. The transport identity itself is RSA-2048 and is **not** quantum-resistant; the payload sealing is what covers harvest-now-decrypt-later.

The pairing port (2324) is plaintext **by design**: the safety number authenticates a pairing, not the channel. It serves only public identity material, is rate-limited, caps requests at 16 KiB, exposes no vault data, and is open only while the Trusted Devices screen is showing.

### How conflicts resolve

Honest answers, because this is where sync tools usually hand-wave:

- **Deleting an entry sticks, and beats a conflicting edit.** A deleted entry leaves a tombstone behind, so the deletion travels with the next sync instead of being undone by it — delete on device A, sync with B, and it is gone on both. If the other device edited the same entry in the meantime, the deletion still wins, whatever the two clocks say; there is no undelete, so re-adding the entry is the way back. Tombstones are dropped after 90 days, so a device that has been out of contact for longer than that can still bring an entry back when it finally syncs. Deleting a **PGP key or keystore** does not propagate — that is file-level sync, see below.
- **Password entries merge by ID.** Every entry on either device survives, unless one of them deleted it.
- **Same entry edited on both devices:** the whole entry with the newer modification time wins — there is no field-level merge. Timestamps are raw device clocks, so a device with a skewed clock consistently wins (or loses); on a tie the local copy stays.
- **Renames are safe** for entries created by current builds. Very old builds derived an entry's ID from its name and username, so a rename of such an entry can show up as a duplicate after sync — delete the extra.
- **PGP keys and keystores are file-level:** same filename means the received copy overwrites yours, with no timestamp comparison; files only one side has are kept. Deletions do not propagate for these — delete the file on both devices.

(The Merge / Overwrite / Skip dialog belongs to the one-way **Settings → Transfer** flow, not to sync — sync never prompts.)

### Troubleshooting

| Symptom | Likely cause / fix |
| --- | --- |
| "Peer did not enter sync mode" | The other device did not tap sync within 60 s. Tap on both, the second within a minute of the first. |
| "Host not paired" | The peer's IP changed since pairing. Re-run pairing with the same device name. |
| Operation not permitted | The peer did not allow that artifact (passwords / PGP / keystores) when pairing. Re-pair with the box checked. |
| Nothing happens at all | Firewall blocking port 2323, or the access point isolates clients (common on guest Wi-Fi). Put both devices on the same normal LAN, and check both run the same app version. |

### Known limits

- Manual only — no background or scheduled sync, and each artifact syncs separately.
- Deleted entries stay deleted for 90 days (see above); deleted PGP keys and keystores still resurrect — delete those on both devices.
- Whole-artifact transfers, no deltas.
- Both devices must run the same build; cross-version sync is unsupported. A build old enough to predate entry history will drop the tombstone on a deleted entry and sync it back alive.
- **PGP key algorithms are part of that.** Keys can be created with RSA, DSA/ElGamal, or one of the
  elliptic-curve options (Ed25519 + Curve25519, NIST ECDSA + ECDH, Ed25519 + X25519, Ed448 + X448).
  A build that predates an algorithm cannot read a key that uses it, so syncing PGP keys to an older
  device will land a key it cannot use — the older device refuses it rather than importing something
  broken. If you sync keys between devices, create them with an algorithm both builds know, or
  update both devices first. RSA and Ed25519 + Curve25519 are the safest choices for interoperating
  with other OpenPGP software; the RFC 9580 codepoints (Ed25519 + X25519, Ed448 + X448) are newer
  than many implementations support.
- Conflict resolution trusts device wall clocks.
- LAN only, by typed IP address; the address is fixed until you re-pair.

## Building

```bash
git clone --recurse-submodules https://github.com/fluxxion82/passman.git
cd passman
./gradlew :apps:droid:assembleDebug   # Android app
./gradlew :apps:desk:run              # Desktop app
```

JDK 17 is required. `--recurse-submodules` matters: [`k2k`](https://github.com/fluxxion82/k2k), the LAN transfer library, lives in its own repo because it is a standalone Apache-2.0 library usable outside this project. If you already cloned without it, `git submodule update --init` fixes things.

## Repository layout

```
apps/droid              Android app
apps/desk               Desktop app (Compose for Desktop)
iosdi                   iOS DI module (port in progress)
presentation/screens    Compose screens
presentation/design     Design system
presentation/viewmodel  ViewModels — depend on domain use-cases only
presentation/viewvo     View value objects
domain                  Use-cases, models, repository contracts
data/*                  crypto, pgp, keystore, cache, repo, local/platform
logging/*               expect/actual logger
build-logic             Included build: the passman.* convention plugins
k2k                     Submodule — LAN transfer library (Apache-2.0)
```

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open public issues for vulnerabilities.

## License

Passman is licensed under the [GNU Affero General Public License v3.0](LICENSE).

The `k2k` submodule is licensed separately under Apache-2.0. Bundled third-party assets are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

# Passman security model

Passman is a local-only password manager. There is no server, no account system, and no key
escrow: your vault lives on your devices, and the only network traffic the app ever produces is
the device-to-device LAN sync described below. This document explains, concretely, how the
cryptography works and what sync actually does on the wire — it is written against the code, not
against intentions. Where a claim depends on a specific source file, a comment in this document's
source names it so maintainers can re-verify.

Scope: this repository (core, Android and desktop apps) plus the `k2k` submodule (LAN
transport). This describes the code as of August 2026. The design is documented in
detail, but the code has **not** had an independent security audit.

---

## 1. The key hierarchy: one password, one memory-hard derivation

The login password is the only secret you know, so it is deliberately the only place a
memory-hard KDF runs. It unwraps a small **device keyring** file, and every other local secret
hangs off that:

```
login password ──Argon2id(64 MiB, t=3, p=1)──▶ wrap key ──unwraps──▶ keyring.pmk ──▶ DMK (32 random bytes)
                                                                                      │
                                          HKDF-SHA256(ikm = DMK, salt = "passman-keyring-v1", info = label)
                                                                                      │
        ┌──────────────────────────────┬──────────────────────────────┬───────────────┴──────────────┐
   passman/vault-wrap/v1     passman/keyfile/hybrid/v1     passman/keyfile/mldsa/v1     passman/pkcs12-password/v1
   wraps the vault root       encrypts hybrid.key           encrypts mldsa.key          the .pfx store password
```

<!-- Argon2id parameters: domain/src/commonMain/kotlin/ai/passman/domain/user/models/KdfParams.kt:32 (64*1024 KiB, t=3, p=1, 32-byte output) -->
<!-- Keyring envelope: data/crypto/src/jvmAndAndroidMain/kotlin/ai/passman/crypto/keyring/KeyringEnvelope.kt -->
<!-- HKDF subkeys and labels: data/crypto/src/jvmAndAndroidMain/kotlin/ai/passman/crypto/keyring/KeyringSubkeys.kt -->

- **Argon2id** (version 1.3, via BouncyCastle) with **64 MiB memory, 3 iterations,
  parallelism 1**, a 48-byte random salt, 32-byte output. Exactly two derivations run per login:
  one to verify the stored credential, one to unwrap the keyring.
- The **Device Master Key (DMK)** is 32 random bytes — *not* derived from your password. It is
  stored only inside `keyring.pmk`, wrapped under **AES-256-GCM**. The entire file header —
  including the declared Argon2id cost parameters and the salt — is bound as GCM associated
  data, so an attacker who rewrites the header to lower the work factor gets an authentication
  failure, not a cheaper key. Cost parameters read from disk are also clamped: floors of
  19 MiB / t=2 (the OWASP minimum configuration) and ceilings of 256 MiB / t=64 / p=16, so a
  tampered header can neither downgrade the KDF nor OOM the process before the tag check.
  <!-- floors: JvmPasswordHasher.kt:61-69; ceilings: KeyringEnvelope.kt:81-83 -->
- Per-purpose subkeys are derived with **HKDF-SHA256** and fixed labels, so the key wrapping the
  vault can never equal the key encrypting a PQ key file.
- **Changing your password rewraps `keyring.pmk` and nothing else.** The DMK does not rotate;
  the vault file and every key file are byte-identical before and after.
- Legacy accounts that predate Argon2id used PBKDF2-HmacSHA256 (130,000 iterations) for the
  login credential; they are transparently re-hashed to the Argon2id parameters on the next
  successful login. <!-- KdfParams.kt: rehash-on-login KDoc -->

## 2. Vault encryption at rest

The vault is a single file per account:
`<data dir>/database/<hash>_encrypted_passman.database`, where `<hash>` is derived from the
username. Its plaintext is a JSON array of password entries (name, username, password, website,
notes, TOTP seed, custom fields, timestamps).
<!-- data/local/platform/src/jvmAndAndroidMain/kotlin/ai/passman/platform/storage/JvmPasswordDatabaseStorage.kt:63 -->

The current envelope ("suite 5") is:

```
magic "PMNV"(4) | version(1)=1 | suite(1)=5 |
rootWrapNonce(12) | wrappedRootKey(32 + 16-byte tag) |
payloadNonce(12) | ciphertext + tag
```

<!-- data/crypto/src/jvmAndAndroidMain/kotlin/ai/passman/crypto/vault/PasswordVaultCipher.kt -->

- Every write draws a **fresh random 32-byte vault root key**, encrypts the JSON under it with
  **AES-256-GCM** (12-byte nonce, 128-bit tag), and wraps the root key under the
  `passman/vault-wrap/v1` subkey, also AES-256-GCM with an independent nonce.
- Both ciphers bind the header bytes in front of them as associated data, so no single-byte edit
  anywhere in the header survives authentication.
- **The vault file contains no KDF parameters and no public-key operation.** An attacker who
  copies only the vault file has nothing to brute-force — they must first break `keyring.pmk`,
  and that costs one full Argon2id derivation (64 MiB, t=3) per password guess.
- Older vaults ("suite 2": RSA-OAEP-wrapped AES-GCM) are still readable and are migrated to
  suite 5 on login; the pre-migration ciphertext is retained once as `<db>.premigration.v2` and
  never deleted by the app, so downgrading to an older build is not a dead end.

**There is no OpenPGP in the vault path.** Passman also ships an OpenPGP feature (section 8),
but the vault format above is its own AEAD envelope, not a PGP message.

## 3. Where keys live on each platform

Per-account identity files live in `<data dir>/keystore/<user>/`:

| File | Contents | Protected by |
| --- | --- | --- |
| `keyring.pmk` | the wrapped DMK | Argon2id over the login password (above) |
| `<user>.pfx` | PKCS#12 identity store (RSA-2048 sync/TLS keypair) | a 256-bit password derived from the DMK — not guessable at any iteration count |
| `hybrid.key` | X25519 + ML-KEM-768 private keys | AES-256-GCM under `passman/keyfile/hybrid/v1` |
| `mldsa.key` | ML-DSA-65 private seed | AES-256-GCM under `passman/keyfile/mldsa/v1` |

- The `.pfx` password is HKDF output (`passman/pkcs12-password/v1`), Base64-encoded — 256 bits
  of randomness. Because that password is not guessable, the store is deliberately written with
  a *minimal* PBE work factor (PBES2, PBKDF2-HmacSHA256 + AES-256-CBC at 2,048 iterations, with
  a PKCS#12 SHA-256 MAC) so it stops being the slow part of login. The iteration count is safe
  *only* because the password is random; keystores you create in the keystore-tools UI with a
  typed password do not go through this writer.
  <!-- data/keystore/src/jvmAndAndroidMain/kotlin/ai/passman/keystore/LowPbePkcs12Writer.kt (ITERATIONS = 2_048 at :87) -->
- Key files are written owner-only, via temp-file + fsync + atomic rename; the first keyring is
  claimed with `O_EXCL` so two racing logins cannot each mint a master key and destroy the
  account. <!-- data/local/platform/src/jvmAndAndroidMain/kotlin/ai/passman/platform/keyring/KeyringStore.kt -->
- These vault and identity files are ordinary files on purpose (so you can back them up); they
  are **not** placed in a hardware keystore. What the platform keystores protect is the app's
  preference storage:
  - **Android**: preferences (login credential record, trusted-device list, PGP/keystore
    metadata) are encrypted with an AES-256-GCM master key generated in and non-exportable from
    the **Android Keystore**. Values get a fresh random IV per write; preference *keys* are
    encrypted deterministically (SHA-256-derived IV) so they can be looked up, which reveals
    key-name equality — inherent to lookup-by-key, and the same property the old
    EncryptedSharedPreferences had. The app also sets `FLAG_SECURE`, so Android blocks
    screenshots and screen recording of it.
    <!-- data/local/platform/src/androidMain/kotlin/ai/passman/platform/prefs/AndroidEncryptionSettingsFactory.kt; apps/droid/src/main/kotlin/ai/passman/android/MainActivity.kt:51 -->
  - **Desktop**: the same scheme, with the AES-256 master key held in the operating system's
    credential store (macOS Keychain / Windows Credential Manager / Linux Secret Service, via
    the `com.microsoft.credentialstorage` library with `SecureOption.REQUIRED`) and the
    encrypted entries in Java Preferences.
    <!-- data/local/platform/src/desktopMain/kotlin/ai/passman/platform/prefs/DesktopEncryptionSettingsFactory.kt -->

**Back up `<data dir>/keystore/<user>/` together with the vault database.** The DMK exists in
exactly one place. There is no recovery service: lose `keyring.pmk` and the vault, both PQ
private keys, and the identity store are unrecoverable even with the correct password.
Restoring only the vault file is safe by design; restoring only the keyring is not.

Separately, each modern profile has a **portable recovery** path: a stable 24-word BIP39 phrase
(256 bits of entropy) that is the password for a standard PKCS#12 recovery file, openable with
stock OpenSSL/keytool without the app. Vault edits, sync, and login-password changes do not
rotate it. See `docs/portable-vault-recovery.md`.
<!-- data/local/platform/src/jvmAndAndroidMain/kotlin/ai/passman/platform/recovery/Bip39RecoveryPhrase.kt -->

## 4. Pairing two devices

Pairing is explicit and mutual. There is no trust-on-first-use: an unpaired host is simply
denied by the data server, and pairing only happens while you are looking at both screens.

1. Open the Trusted Devices screen on both devices. Only then does each device start a
   **pairing listener on TCP port 2324**. It serves exactly one thing — a device identity
   bundle over plain HTTP (`GET`/`POST /pairing-bundle`) — and it stops when you leave the
   screen. No vault data, uploads, or downloads are reachable on this port.
   <!-- k2k/k2k/src/jvmMain/kotlin/com/k2k/test/server/server.kt (pairing mode registers no data routes); presentation/viewmodel/.../connectivity/TrustedDevicesViewModel.kt:109-118 -->
2. One device enters the other's IP address (each device displays its own address; there is no
   broadcast discovery — see section 5). The devices exchange identity bundles containing: the
   RSA-2048 TLS public key (SPKI), the hybrid public key (X25519, 32 bytes + ML-KEM-768,
   1,184 bytes), the ML-DSA-65 public key (1,952 bytes), and a capability bitfield.
   Deliberately no display name: renaming a device must never change its cryptographic identity.
   <!-- domain/src/commonMain/kotlin/ai/passman/domain/connectivity/model/DeviceIdentityBundle.kt -->
3. Both screens display the same **safety number**:
   `SHA-256("passman-device-safety-number-v1" | bundleA | bundleB)`, with the two bundle
   encodings ordered by their own digests so the number is identical on both sides. It is shown
   as 25 decimal digits in five groups of five. **Compare them by eye and confirm on both
   devices.** Nothing is persisted until you confirm; a mismatch means an on-path attacker or a
   mistyped address, and cancelling leaves no record.
4. On confirmation each device pins the peer's RSA SPKI, hybrid key, and ML-DSA key. Those
   pinned copies are what every future sync verifies against — they are never re-fetched.

The pairing exchange is plaintext by design (there is no shared trust yet to authenticate a TLS
channel with); its authenticity comes entirely from the humans comparing the safety number. The
Android app's network security config permits cleartext HTTP for exactly this bootstrap.
<!-- apps/droid/src/main/res/xml/network_security_config.xml -->

Each pairing carries a security state:

| State | Meaning |
| --- | --- |
| `LegacyRsa` | Pre-ceremony pairing. Syncs with classical (suite v2/v3) payloads until you run "Upgrade pairing security". |
| `AwaitingConfirmation` | The peer's stored PQ keys went stale (e.g. this device had to regenerate a quarantined key file). Sync is refused in both directions until the ceremony is re-run. |
| `SignedHybridRequired` | Ceremony confirmed. Only signed post-quantum (suite v4) payloads are accepted, and only under the exact keys pinned at pairing. |

A successful transfer never promotes a pairing; only the confirmed ceremony does.

## 5. What sync actually does

This is the answer to "sync is opaque". The whole flow, in order:

**Discovery: there is none.** The k2k library contains a UDP broadcast discovery component, but
the app never invokes it — the only k2k pieces Passman uses are the HTTP server/client and the
TLS helpers. You type (or re-use) the peer's IP address; each device shows its own. If you see
Passman traffic you did not initiate, that is a bug worth reporting.

**Transport: mutual TLS on TCP port 2323.** Each device presents its self-signed RSA-2048
certificate. The server *requires* a client certificate (`ClientAuth.REQUIRE`) and accepts only
certificates whose SubjectPublicKeyInfo SHA-256 pin matches a paired device; the client pins the
server to the stored fingerprint of the device at that address. TLS 1.3 is preferred, 1.2
permitted; there is no plaintext fallback, and with zero paired devices the server trusts nobody
(fails closed). The data server runs only during an active sync session or while receive mode is
on — not permanently in the background.
<!-- k2k/k2k/src/jvmSources/kotlin/com/k2k/test/tls/K2kTls.kt:85-93; data/repo/src/jvmAndAndroidMain/kotlin/ai/passman/repo/tls/SyncTlsProvider.kt -->

**Payload encryption: a second layer inside TLS.** Every artifact that crosses the wire is also
encrypted end-to-end as an application-layer envelope, keyed per pairing state:

- **Upgraded pairings (`SignedHybridRequired`), suite v4:** the payload is sealed with a hybrid
  KEM — a fresh ephemeral **X25519** agreement *and* a fresh **ML-KEM-768** encapsulation,
  concatenated and run through HKDF-SHA256 (an AND-construction: confidentiality holds unless
  both are broken), producing an AES-256-GCM key. Inside the ciphertext, the payload carries an
  **ML-DSA-65** signature over the envelope transcript, verified against the ML-DSA key pinned
  at pairing. The recipient encrypts to the hybrid key pinned at pairing — key material is never
  fetched over the wire for these pairings, and an unsigned envelope, or a valid signature under
  any other key, is rejected before anything is written.
  <!-- data/crypto/src/jvmAndAndroidMain/kotlin/ai/passman/crypto/HybridKem.kt; .../crypto/MlDsa.kt (ml_dsa_65); .../platform/repository/InboundSyncPolicy.kt -->
- **Legacy pairings (`LegacyRsa`), suite v2/v3:** RSA-OAEP + AES-GCM, or unsigned hybrid, with
  peer keys fetched over the pinned mTLS channel each sync. This is what pre-ceremony pairings
  exchange until you upgrade them.

**A sync session** (you tap Sync on both devices, within 60 seconds of each other):

1. The app checks the target address belongs to a paired, non-quarantined device and starts its
   own receive server.
2. It pushes its encrypted vault to the peer, retrying every 3 s for up to 60 s while the peer's
   server comes up.
3. On the first successful push it immediately pulls the peer's vault, then holds its own server
   open until the peer has completed the same push+pull handshake (or the 60 s window ends), so
   the slower device is not cut off.
4. The server stops when the session ends, however it ends.
<!-- domain/src/commonMain/kotlin/ai/passman/domain/settings/SyncPasswords.kt (runSyncSession) -->

**What moves:** the encrypted password vault; and, if the pairing's per-device permission list
allows those operations, the OpenPGP keyring bundle and the keystore-tools bundle — each a
separate artifact with the same envelope rules. Each paired device has an operation allowlist
checked per request on the receiving side, on top of the TLS pinning. The device identity files
(`keyring.pmk`, `hybrid.key`, `mldsa.key`, `<user>.pfx`, the recovery artifacts) are excluded
from every sync bundle in both directions — each device keeps its own.
<!-- SyncTlsProvider.authorize; ArtifactSyncClient.kt (SyncArtifact kinds); KeyringStore.kt KDoc (DirectoryBundler.syncExclusions) -->

**Merging:** an inbound vault is staged in `database/tmp`, and the app tells you it arrived and
whether it conflicts. Nothing touches your live vault until you choose **Merge**, **Overwrite**
(take theirs), or **Delete** (discard theirs). Merge is keyed on each entry's UUID:
**whole-entry, newest-wins** — the copy with the later `dateCreated` (which is bumped on every
edit, so it is effectively last-modified) replaces the other completely. The result is
re-encrypted as a fresh suite-5 envelope under this device's own keys; wire formats never
persist to disk.
<!-- data/local/platform/src/jvmAndAndroidMain/kotlin/ai/passman/platform/repository/VaultReconciler.kt:81-89; LocalPasswordRepository.kt:258 (edit bumps dateCreated) -->

**What a passive network observer sees:** which IPs talk to each other, the ports (2323/2324),
connection timing, and approximate payload sizes. During pairing they also see the public
identity bundles — public keys only, and substituting them is what the safety-number comparison
detects. During sync the payload is TLS-encrypted and *additionally* envelope-encrypted; for
upgraded pairings that inner envelope is post-quantum, so recorded sync traffic stays
confidential even against a future quantum adversary ("harvest now, decrypt later" is covered).
When TLS 1.2 is negotiated the certificate exchange itself is visible, which reveals the
devices' self-signed certificates (public keys, not secrets). The transport *identity* is
RSA-2048 and is not quantum-resistant — an accepted, documented limit (section 10): stock TLS
cannot negotiate ML-KEM/ML-DSA certificates, and against upgraded pairings a transport-level
impersonator still cannot read or forge payloads, which are bound to the pinned PQ keys.

## 6. Login rate limiting — and why it is in-memory on purpose

The unlock screen allows 5 free attempts; from the 6th consecutive failure a cooldown starts at
30 seconds, doubles per failure, and caps at 5 minutes. A successful login resets it. The
counter is **deliberately in-memory only** — killing the app clears it.
<!-- domain/src/commonMain/kotlin/ai/passman/domain/user/LoginAttemptThrottle.kt -->

That looks like a bug until you consider who it defends against. An attacker who has your device
does not type guesses into the unlock screen — they copy `keyring.pmk` and the vault file and
run Argon2id offline, where no app-side counter, persisted or not, exists at all. The real
brute-force defense is the 64 MiB / t=3 Argon2id cost on the file itself (section 1). The
throttle's only job is to keep the UI from being a free guessing oracle for someone briefly
holding your unlocked phone; persisting it would add lockout-file complexity (and a
denial-of-service surface) without changing the offline math it cannot affect.

## 7. TOTP

TOTP secrets are ordinary entry fields (`totpSeed`): they live inside the vault JSON and are
encrypted, synced, and merged exactly like passwords. There is no second store. Code generation
is a self-contained RFC 6238 / RFC 4226 implementation in the domain layer — hand-written
HMAC-SHA1 in pure Kotlin (no platform crypto dependency), 6–8 digits, 30-second default period.
`otpauth://` imports accept SHA-1 (the standard authenticator default) and reject other
algorithms rather than silently generating wrong codes.
<!-- domain/src/commonMain/kotlin/ai/passman/domain/password/totp/ (TotpGenerator.kt, TotpConfig.kt, HmacSha1.kt) -->

## 8. The OpenPGP feature

Separate from the vault, Passman can manage OpenPGP keyrings (BouncyCastle `bcpg`) for
encrypting/signing files and text:

- Messages: AES-256 with the integrity-protected packet (SEIPD). Signatures use SHA-256/SHA-512.
- Secret keys: AES-256, with an iterated-and-salted S2K over SHA-256. Rings protected by a
  passphrase you typed use the maximum S2K count (coded 0xFF, ≈65 MB hashed). Rings the app
  provisions with a *generated* ~157-bit passphrase use the RFC 4880 baseline count (0x60,
  64 KiB hashed) — stretching adds nothing against that much entropy, and the maximum costs
  seconds per key on a phone. If such a ring is ever re-sealed with a typed passphrase, it goes
  back to 0xFF. <!-- data/pgp/.../utils/PgpKeys.kt:75-83; .../service/PgpClient.kt:39-48 -->
- OpenPGP stays classical. `bcpg` has no RFC 9980 (PQ OpenPGP) support yet, and Passman will not
  invent a private packet format and call it OpenPGP.

## 9. What Passman does not do

Verified against the codebase, not just asserted:

- **No server, no accounts.** Nothing to sign up for; no cloud copy of anything.
- **No telemetry, analytics, or crash reporting.** There are no analytics/crash SDK dependencies
  and no such network calls in either app.
- **No network traffic except what section 5 describes** — the pairing listener (2324, only
  while the Trusted Devices screen is open), the sync data server (2323, mTLS-only), and the
  sync client talking to a LAN address you chose. No update checks, no version pings, no
  outbound internet URLs in the apps.
- **No background sync.** Every session is user-initiated on both ends.

## 10. Known limitations

Honest list, in rough order of how much they matter:

- **Transport identity is RSA-2048** (sections 4–5). A quantum adversary could impersonate a
  paired device at the TLS layer; against upgraded pairings they still could not read recorded
  traffic or forge a payload. Accepted risk, revisited when PQ certificates are practical.
- **Pairings still in `LegacyRsa` get weaker envelope guarantees** until you run the upgrade
  ceremony: classical RSA-OAEP (suite v2) payloads are still accepted, envelope signatures are
  not required, and peer keys are fetched over the wire instead of pinned. The PQ guarantees are
  a property of upgraded pairings, not of every byte on the wire.
- **A compromised paired device is a standing read capability** for whatever operations its
  pairing allows, while your vault is unlocked. Removing a device stops future syncs; it cannot
  revoke data the device already copied.
- **Merge is whole-entry.** Newest-wins per entry means concurrent edits to *different fields*
  of the same entry on two devices keep only one side's changes. Corollary (and why
  cross-version sync is unsupported — both devices must run the same build): a peer on an older
  build that edits an entry re-serializes only the fields it knows, and if that copy wins the
  merge, fields it never knew (`totpSeed`, `customFields`) are silently dropped.
- **The login throttle resets on process death** — by design; see section 6 for why that is not
  the defense layer.
- **Memory hygiene is best-effort.** Key material is zeroed in `finally` blocks on every path,
  but the JVM copies key bytes internally (`SecretKeySpec`, cipher buffers, the immutable
  `String` PKCS#12 password), so wiping shrinks the exposure window rather than closing it.
  Closing it would require native memory management the JVM layer does not have.
  <!-- e.g. PasswordVaultCipher.kt KDoc, HybridKem.wipe, KeyringSubkeys.pkcs12Password -->
- **Clipboard.** Copied secrets are cleared after a configurable expiry (default: on, 30 s), and
  the clear is careful never to wipe something you copied afterwards — but it is best-effort,
  you can disable it, and OS-level clipboard history/managers and clipboard-reading apps are
  outside Passman's control. <!-- ExpiringClipboard.kt; ClipboardExpiry.Default = 30s -->
- **Screenshots are blocked on Android only** (`FLAG_SECURE`). Desktop OSes offer no equivalent;
  treat screen-sharing with the vault open accordingly.
- **Losing `keyring.pmk` loses the account** (section 3). That is the price of no escrow; the
  24-word portable recovery phrase exists so you can make the trade-off explicit.
- **Encrypted preferences reveal key-name equality** (deterministic key encryption, needed for
  lookup) — metadata about *which* settings exist, never their values.
- **iOS is not yet a supported platform**: the shared types compile for iOS, but the keyring and
  vault cipher have no iOS implementations.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md) in the repo root. Please do not open a public issue for a
security report.

package ai.passman.platform.repository

import kotlinx.serialization.json.Json

/**
 * The one codec every vault entry list goes through — repository reads, sync-pull merges, and the
 * reconcile paths in `FileTransferRepository` alike.
 *
 * ## `ignoreUnknownKeys = true` is a decision, not a default
 *
 * Strict decoding looks like the safer setting for a vault, but the strictness never guards what it
 * appears to guard. Every byte of vault plaintext comes out of a successful AES-GCM decrypt —
 * corruption and tampering die at the authentication tag, before any JSON exists to be strict
 * about. The only way an unknown key reaches this decoder is a **newer build of this app** having
 * written the row, and rejecting that is a policy of "every added field breaks cross-version sync".
 * Task 5b's `uuid` field paid that cost in full: a strict peer on the previous build cannot parse a
 * sync pull from an upgraded device. This release requires updating both devices regardless, so the
 * break is already spent — tolerating unknown keys here is what keeps the *next* field addition
 * from breaking sync the same way.
 *
 * What this deliberately does not loosen: plaintext that is not an entry list at all still fails to
 * decode, still reads as unreadable, and still leaves the ciphertext untouched
 * (`VaultDecoderStrictnessTest` pins the boundary).
 *
 * One instance rather than per-site `Json {}` blocks so the read and write sides cannot drift apart
 * field by field.
 */
internal val VaultJson = Json { ignoreUnknownKeys = true }

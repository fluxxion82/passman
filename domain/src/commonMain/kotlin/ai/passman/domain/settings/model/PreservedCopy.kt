package ai.passman.domain.settings.model

/**
 * A version of a synced artifact that an inbound sync displaced, still on this device.
 *
 * Sync merges artifact directories by filename, so it cannot tell "same artifact, newer bytes" from
 * "different artifact, same name". Rather than guess, it never replaces a file without first moving
 * the bytes it is displacing aside. On the PGP side those bytes are a secret ring, and a lost one is
 * a private key that exists nowhere else — which is why these are surfaced rather than quietly kept.
 *
 * These accumulate on ordinary use, not only on genuine conflicts: every propagated key edit
 * displaces the receiving device's copy, and rewrites are salt-randomised, so byte-different is the
 * normal result of a semantically identical change. That is the reason this is a screen the user can
 * clear rather than a hidden directory — superseded rings under retired passphrases must not pile up
 * where nothing can delete them.
 *
 * @property id the copy's filename in the store, and the handle every operation takes. Opaque:
 *   callers must pass back what they were given rather than construct one.
 * @property originalName the path within the artifact directory this was displaced from.
 * @property modifiedAt the artifact's own last-modified time, carried across by the move — when this
 *   *version* was written, not when it was displaced.
 * @property restorable whether the path this came from was recorded in full. False for a path too
 *   long to fit a filename: the bytes are intact and still exportable, but the destination is
 *   unknown, and restoring to a guessed one would write a file nobody asked for while leaving the
 *   artifact it was meant to replace untouched.
 */
data class PreservedCopy(
    val artifact: String,
    val id: String,
    val originalName: String,
    val sizeBytes: Long,
    val modifiedAt: Long,
    val restorable: Boolean = true,
)

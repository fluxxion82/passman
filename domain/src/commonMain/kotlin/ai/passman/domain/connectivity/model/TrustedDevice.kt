package ai.passman.domain.connectivity.model

import kotlinx.serialization.Serializable

/** The distinct sync operations a trusted device can be authorized for, individually. */
object SyncOps {
    const val PASSWORDS = "passwords"
    const val PGP = "pgp-keys"
    const val KEYSTORE = "keystore"
    val ALL: Set<String> = setOf(PASSWORDS, PGP, KEYSTORE)
}

/**
 * A peer device the user has explicitly trusted by confirming its public-key fingerprint
 * out-of-band (typically by comparing fingerprints side-by-side at pairing time).
 *
 * The transport pins each connection to [fingerprint] (SPKI pin) over mutual TLS, so only paired
 * devices can connect at all. [allowedOps] narrows this further per device: a device paired for
 * password sync need not be allowed to push/pull PGP keys or keystores. Defaults to all ops for
 * backward compatibility with pairings stored before per-op authz existed.
 */
@Serializable
data class TrustedDevice(
    val name: String,
    /** Frozen RSA SPKI mTLS pin. Composite identity material must never replace this value. */
    val fingerprint: String,
    val lastHost: String,
    val lastSyncedAt: Long = 0L,
    val allowedOps: Set<String> = SyncOps.ALL,
    val hybridPublicKey: String? = null,
    val mldsaPublicKey: String? = null,
    val identityDigest: String? = null,
    val pairingSecurity: PairingSecurity = PairingSecurity.LegacyRsa,
)

/** The security level accepted for a persisted pairing. */
@Serializable
enum class PairingSecurity {
    /** Existing RSA-SPKI-pinned pairing that has not completed the post-quantum ceremony. */
    LegacyRsa,

    /** A previous signed pairing needs an explicit new safety-number confirmation before it can sync. */
    AwaitingConfirmation,

    /** Both peer PQ public keys were confirmed and signed hybrid sync is required. */
    SignedHybridRequired,
}

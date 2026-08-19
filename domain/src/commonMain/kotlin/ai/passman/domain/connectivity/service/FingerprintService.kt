package ai.passman.domain.connectivity.service

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.PairingQrPayload

/**
 * Platform-provided helpers for computing and fetching public-key fingerprints.
 *
 * Implementations should produce a stable string format (e.g. SHA-256 hex with colons every
 * two bytes) so users can compare fingerprints visually between devices during pairing.
 */
interface FingerprintService {
    /** SHA-256 (on JVM/Android) of arbitrary bytes, kept behind this platform seam for commonMain. */
    fun digest(bytes: ByteArray): ByteArray

    /**
     * HMAC-SHA256 over [data] under [key], behind this platform seam like [digest]. The QR pairing
     * possession proof is the only caller: whoever scanned the code holds the nonce it keys on.
     */
    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray

    /**
     * [count] cryptographically secure random bytes, for pairing nonces. A predictable draw here is
     * a QR whose possession proof anyone can forge, so implementations must not use a plain PRNG.
     */
    fun randomBytes(count: Int): ByteArray

    /** Compute a stable fingerprint of arbitrary public-key bytes. */
    fun fingerprintOf(publicKeyBytes: ByteArray): String

    /** Fingerprint of the local user's transfer public key (the one peers receive). */
    suspend fun getOwnFingerprint(): Outcome<String>

    /**
     * Fetch the peer's transfer pubkey from [host]:[port] and fingerprint it. Defaults to the
     * plaintext pairing port (2324) — the data port (2323) is TLS-only and refuses the unpinned
     * fetch a first-time pairing needs.
     */
    suspend fun fetchPeerFingerprint(host: String, port: Int = PairingQrPayload.DEFAULT_PAIRING_PORT): Outcome<String>

    /** Build this device's public pairing identity. Private key material must never cross this seam. */
    suspend fun getOwnDeviceIdentityBundle(): Outcome<DeviceIdentityBundle>

    /** Fetch and validate a peer's bounded public identity bundle from the pairing listener. */
    suspend fun fetchPeerDeviceIdentityBundle(
        host: String,
        port: Int = PairingQrPayload.DEFAULT_PAIRING_PORT,
    ): Outcome<DeviceIdentityBundle>

    /**
     * Deliver the local public identity bundle to the peer during the explicit pairing exchange.
     *
     * [proofBase64Url] is the QR possession proof — an HMAC over both canonical bundles, keyed on the
     * nonce the scanned code carried — and is null for a ceremony no code started. Implementations
     * attach it to the push as the `X-Passman-Pairing-Proof` header rather than folding it into the
     * bundle, so a peer that never showed a code simply never reads it and old peers ignore it.
     */
    suspend fun pushDeviceIdentityBundle(
        bundle: DeviceIdentityBundle,
        host: String,
        port: Int = PairingQrPayload.DEFAULT_PAIRING_PORT,
        proofBase64Url: String? = null,
    ): Outcome<Unit>
}

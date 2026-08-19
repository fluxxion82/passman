package ai.passman.platform.transfer

import ai.passman.crypto.EnvelopeCodec
import ai.passman.crypto.HybridKem
import ai.passman.crypto.MlDsa
import ai.passman.domain.connectivity.model.TrustedDevice
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * Decoders for the peer key material persisted on a [TrustedDevice] when the user confirmed the
 * safety-number ceremony (Base64, written by `ConfirmDevicePairing`).
 *
 * For a `SignedHybridRequired` pairing these stored values — never keys fetched over the wire —
 * are the only acceptable source of the peer's encryption and signature-verification keys: a key
 * served over the connection is authenticated no more strongly than the transport, and the whole
 * point of the signed-hybrid policy is that payload authenticity must not rest on the (classical
 * RSA) transport alone.
 *
 * Both decoders return null rather than throwing on absent or damaged fields; the callers treat
 * null as "refuse the operation", never as "fall back to fetching the key".
 */
@OptIn(ExperimentalEncodingApi::class)
object StoredPeerKeys {
    /** The hybrid (X25519+ML-KEM) recipient key persisted at pairing, or null if absent/undecodable. */
    fun hybridRecipient(device: TrustedDevice): HybridKem.HybridPublicKey? =
        device.hybridPublicKey
            ?.let { runCatching { EnvelopeCodec.deserializePublicKey(Base64.Default.decode(it)) }.getOrNull() }

    /** The ML-DSA-65 verify key persisted at pairing, or null if absent, undecodable, or mis-sized. */
    fun mldsaVerifyKey(device: TrustedDevice): ByteArray? =
        device.mldsaPublicKey
            ?.let { runCatching { Base64.Default.decode(it) }.getOrNull() }
            ?.takeIf { it.size == MlDsa.PUBLIC_KEY_BYTES }

    /**
     * The uniform refusal for an `AwaitingConfirmation` pairing. One string on purpose: sender- and
     * receiver-side refusals must be recognisably the same policy, and tests key on this text.
     */
    fun reverificationRefusal(deviceName: String): String =
        "sync refused: pairing with '$deviceName' requires re-verification before it may sync again"
}

package ai.passman.domain.connectivity

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * The two halves of the QR possession proof that both ends of the ceremony must agree on.
 *
 * [BeginDevicePairing] computes and encodes the proof; [QrPairingSession] decodes and checks it. They
 * are the same wire value read from opposite sides, so the codec and the comparison live here rather
 * than being spelled twice — a second copy that drifted would look like a working build and fail only
 * as a pairing that silently never verifies.
 */

/** Base64 variant for the QR possession proof: url-safe, no padding. Frozen wire format. */
@OptIn(ExperimentalEncodingApi::class)
internal val PROOF_BASE64: Base64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

/**
 * Timing-independent comparison; proofs and digests are attacker-supplied on a plaintext port.
 *
 * The running time depends on the lengths only, never on where two byte arrays first differ.
 * `contentEquals` would return on the first mismatch and hand an attacker pushing guesses at the
 * pairing port a byte-at-a-time path to a forged proof.
 */
internal fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var accumulator = 0
    for (index in a.indices) {
        accumulator = accumulator or (a[index].toInt() xor b[index].toInt())
    }
    return accumulator == 0
}

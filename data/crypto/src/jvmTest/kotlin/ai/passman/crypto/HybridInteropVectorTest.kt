package ai.passman.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals

/**
 * Byte-level interop anchor for the suite-v3 hybrid envelope. A frozen envelope (produced by this
 * JVM implementation) must always decrypt, with the frozen private key, to the frozen plaintext.
 *
 * Purpose: (1) regression — any accidental change to the envelope layout, the HKDF combiner, the
 * transcript binding, or the ML-KEM/X25519 wiring breaks this test; (2) cross-platform interop — the
 * future iOS implementation must decrypt this exact vector (same resource file) to prove format
 * agreement before it is trusted for real data.
 */
class HybridInteropVectorTest {
    private fun loadVector(): Map<String, ByteArray> {
        val stream = javaClass.getResourceAsStream("/vectors/hybrid-v3-vector.txt")
            ?: Thread.currentThread().contextClassLoader?.getResourceAsStream("vectors/hybrid-v3-vector.txt")
            ?: error("missing vectors/hybrid-v3-vector.txt")
        return stream.bufferedReader().useLines { lines ->
            lines.filter { it.contains('=') }.associate { line ->
                val (k, v) = line.split('=', limit = 2)
                k.removePrefix("VEC_") to v.trim().hexToByteArray()
            }
        }
    }

    private fun String.hexToByteArray(): ByteArray =
        chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun frozenEnvelopeDecryptsToKnownPlaintext() {
        val v = loadVector()
        val priv = HybridKem.HybridPrivateKey(x25519 = v.getValue("X25519_PRIV"), mlkem = v.getValue("MLKEM_PRIV"))
        val decrypted = HybridKem.decrypt(v.getValue("ENVELOPE"), priv)
        assertContentEquals(v.getValue("PLAINTEXT"), decrypted)
    }
}

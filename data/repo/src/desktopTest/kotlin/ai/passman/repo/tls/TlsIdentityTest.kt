package ai.passman.repo.tls

import com.k2k.test.tls.SpkiPinning
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.cert.X509Certificate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class TlsIdentityTest {

    // Replicates the fingerprint service format: SHA-256 of the public key DER, colon-separated
    // upper-case hex — this is what a peer stores for this device at pairing time.
    private fun peerFingerprint(publicKeyDer: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(publicKeyDer)
            .joinToString(":") { "%02X".format(it.toInt() and 0xFF) }

    private fun rsaKeyPair() =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()

    @Test
    fun generatedCertPin_matchesNormalizedPeerFingerprint() {
        val kp = rsaKeyPair()
        val fingerprint = peerFingerprint(kp.public.encoded)

        val ks = TlsIdentity.buildSessionKeyStore(kp.private, kp.public, "pw".toCharArray())
        val cert = ks.getCertificate(TlsIdentity.ALIAS) as X509Certificate

        // The whole integration hinges on this: the TLS cert minted over the identity key pins to
        // exactly the fingerprint the peer already stored. Cross-checked against the transport's
        // own pin function so both modules agree byte-for-byte.
        assertEquals(TlsIdentity.fingerprintToPin(fingerprint), SpkiPinning.pinOf(cert))
    }

    @Test
    fun fingerprintToPin_stripsSeparatorsAndLowercases() {
        assertEquals("aabbcc0011", TlsIdentity.fingerprintToPin("AA:BB:CC:00:11"))
    }

    @Test
    fun sessionKeyStore_holdsPrivateKeyUnderAlias() {
        val kp = rsaKeyPair()
        val ks = TlsIdentity.buildSessionKeyStore(kp.private, kp.public, "pw".toCharArray())
        assertTrue(ks.isKeyEntry(TlsIdentity.ALIAS))
        assertNotNull(ks.getKey(TlsIdentity.ALIAS, "pw".toCharArray()))
        assertEquals(1, ks.getCertificateChain(TlsIdentity.ALIAS).size)
    }
}

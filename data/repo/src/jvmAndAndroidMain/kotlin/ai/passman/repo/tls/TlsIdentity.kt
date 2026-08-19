package ai.passman.repo.tls

import java.math.BigInteger
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Calendar
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

/**
 * Bridges the app's existing device identity (the `passmanMain` RSA key + its public-key
 * fingerprint) to the k2k transport's mutual-TLS layer.
 *
 * Key insight: the SPKI pin the transport checks is `SHA-256(cert.publicKey.encoded)`, and the
 * peer fingerprint stored at pairing is `SHA-256(publicKey.encoded)` of the *same* identity key.
 * So a TLS certificate freshly generated over the session's identity key has a pin identical to the
 * stored fingerprint (modulo formatting) — no new key material and no schema change are needed.
 *
 * The raw login password is not available at sync time (only its PBKDF2 hash is), so we cannot
 * reload the `.pfx`. Instead we mint an in-memory keystore from the already-unwrapped session key
 * plus a self-signed certificate over it. The certificate is disposable; only the key it binds
 * (and therefore the pin) is stable.
 */
object TlsIdentity {
    const val ALIAS = "passmanTls"

    /**
     * Normalise a colon-separated, upper-case fingerprint (as produced by the fingerprint service)
     * to the transport's pin form: lower-case hex, no separators.
     */
    fun fingerprintToPin(fingerprint: String): String =
        fingerprint.replace(":", "").lowercase()

    /**
     * Build an in-memory PKCS#12 keystore holding [privateKey] and a self-signed certificate over
     * [publicKey], under [ALIAS], protected by [password]. Suitable for both the k2k server and
     * client TLS material. The certificate's SPKI equals the identity key's, so its pin matches the
     * peer-stored fingerprint of this device.
     */
    fun buildSessionKeyStore(privateKey: PrivateKey, publicKey: PublicKey, password: CharArray): KeyStore {
        val cert = selfSignedCertificate(privateKey, publicKey)
        return KeyStore.getInstance("PKCS12").apply {
            load(null, null)
            setKeyEntry(ALIAS, privateKey, password, arrayOf(cert))
        }
    }

    private fun selfSignedCertificate(privateKey: PrivateKey, publicKey: PublicKey): X509Certificate {
        val name = X500Name("CN=passman-tls")
        val serial = BigInteger(64, SecureRandom())
        val notBefore = Date(System.currentTimeMillis() - 60_000)
        val notAfter = Calendar.getInstance().apply { add(Calendar.YEAR, 2) }.time
        val builder = JcaX509v3CertificateBuilder(name, serial, notBefore, notAfter, name, publicKey).apply {
            addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            addExtension(
                Extension.keyUsage,
                true,
                KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment),
            )
            addExtension(
                Extension.extendedKeyUsage,
                false,
                ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth)),
            )
        }
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(privateKey)
        return JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider())
            .getCertificate(builder.build(signer))
    }
}

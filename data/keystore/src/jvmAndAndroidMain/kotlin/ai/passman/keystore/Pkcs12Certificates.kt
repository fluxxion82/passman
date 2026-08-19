package ai.passman.keystore

import java.math.BigInteger
import java.security.KeyPair
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

/** Certificate construction shared by the app identity and the portable recovery P12. */
object Pkcs12Certificates {
    private const val VALIDITY_DAYS = 3650L

    fun selfSignedRsa(keyPair: KeyPair, commonName: String): X509Certificate {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
        val name = X500Name("CN=$commonName,O=Passman")
        val now = Date()
        val until = Date(now.time + VALIDITY_DAYS * 24 * 60 * 60 * 1000)
        val serial = BigInteger(160, SecureRandom()).abs()
        val builder = JcaX509v3CertificateBuilder(name, serial, now, until, name, keyPair.public).apply {
            addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            addExtension(
                Extension.keyUsage,
                true,
                KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment or KeyUsage.dataEncipherment),
            )
        }
        val signer = JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .build(keyPair.private)
        return JcaX509CertificateConverter()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME)
            .getCertificate(builder.build(signer))
    }
}

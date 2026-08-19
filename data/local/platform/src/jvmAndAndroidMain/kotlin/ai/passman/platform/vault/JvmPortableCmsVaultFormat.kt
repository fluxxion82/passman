package ai.passman.platform.vault

import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.platform.recovery.JvmPortableVaultRecovery
import java.security.Security
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cms.CMSAlgorithm
import org.bouncycastle.cms.CMSEnvelopedData
import org.bouncycastle.cms.CMSEnvelopedDataGenerator
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder

/** CMS `EnvelopedData(SignedData(JSON))` backed by a profile's recovery P12. */
class JvmPortableCmsVaultFormat(
    private val recovery: JvmPortableVaultRecovery,
) : PortableVaultFormat {
    override fun seal(username: String, plaintext: ByteArray, sessionKey: VaultSessionKey): ByteArray {
        val material = recovery.material(username, sessionKey)
        ensureBouncyCastle()
        val signed = CMSSignedDataGenerator().run {
            val signer = JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(material.privateKey)
            val digests = JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build()
            addSignerInfoGenerator(JcaSignerInfoGeneratorBuilder(digests).build(signer, material.certificate))
            addCertificates(JcaCertStore(listOf(material.certificate)))
            generate(CMSProcessableByteArray(plaintext), true).encoded
        }
        return CMSEnvelopedDataGenerator().run {
            addRecipientInfoGenerator(
                JceKeyTransRecipientInfoGenerator(material.certificate)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME),
            )
            generate(
                CMSProcessableByteArray(signed),
                JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(),
            ).encoded
        }
    }

    override fun open(username: String, ciphertext: ByteArray, sessionKey: VaultSessionKey): ByteArray {
        val material = recovery.material(username, sessionKey)
        ensureBouncyCastle()
        val envelope = CMSEnvelopedData(ciphertext)
        val recipient = envelope.recipientInfos.recipients.singleOrNull()
            ?: throw IllegalArgumentException("portable vault must have exactly one recipient")
        val signedBytes = recipient.getContent(
            JceKeyTransEnvelopedRecipient(material.privateKey).setProvider(BouncyCastleProvider.PROVIDER_NAME),
        )
        val signed = CMSSignedData(signedBytes)
        val signer = signed.signerInfos.signers.singleOrNull()
            ?: throw IllegalArgumentException("portable vault must have exactly one signer")
        // Verify against the keyring-pinned certificate rather than trusting whichever certificate
        // the untrusted CMS object carries.  A missing embedded certificate is allowed because the
        // exact signer is already pinned locally.
        check(signer.verify(JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(material.certificate))) {
            "portable vault signature did not verify"
        }
        return signed.signedContent?.content as? ByteArray
            ?: throw IllegalArgumentException("portable vault has detached or non-byte content")
    }

    override fun isPortable(ciphertext: ByteArray): Boolean =
        runCatching { CMSEnvelopedData(ciphertext); true }.getOrDefault(false)

    private fun ensureBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }
}

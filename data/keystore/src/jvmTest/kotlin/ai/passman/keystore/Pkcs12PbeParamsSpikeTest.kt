package ai.passman.keystore

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.FileInputStream
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.Security
import java.security.cert.CertificateFactory
import javax.crypto.Cipher
import javax.crypto.spec.PBEParameterSpec
import kotlin.system.measureTimeMillis
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe
import org.bouncycastle.asn1.pkcs.EncryptedData
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.MacData
import org.bouncycastle.asn1.pkcs.PBES2Parameters
import org.bouncycastle.asn1.pkcs.PBKDF2Params
import org.bouncycastle.asn1.pkcs.PKCS12PBEParams
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.Pfx
import org.bouncycastle.asn1.pkcs.SafeBag
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.jcajce.PKCS12StoreParameter
import org.bouncycastle.jce.provider.BouncyCastleProvider

/**
 * Empirical BC 1.85/JDK 17 result: no JCA-only route produces low-PBE, dual-provider PKCS#12.
 * JDK's inherited `KeyStoreSpi.engineSetEntry` rejects every non-null
 * `PasswordProtection.protectionAlgorithm`; thus the requested
 * `PBEWithHmacSHA256AndAES_256` never reaches BC. BC does expose
 * `PBEWithSHA256And256BitAES-CBC-BC` as a Cipher, but `setEntry` rejects it too. Standard
 * `KeyStore.getInstance("PKCS12", "BC")` fixes key/cert PBE at 600,000 and MAC at 1,200,000;
 * its `PKCS12StoreParameter` ignores `setMacAlgorithm`, and the three `keystore.pkcs12.*`
 * system properties do not affect BC.
 *
 * The only caller-controlled MAC route is `KeyStore.getInstance("PKCS12-PBMAC1", "BC")`, then
 * `store(PKCS12StoreParameter.builder(out, password).setMacAlgorithm(
 * PKCS12StoreParameter.pbmac1WithPBKDF2Builder().setSalt(salt).setIterationCount(2048).build())
 * .build())`. It writes PBMAC1/PBKDF2 with 2,048 iterations, but still writes 600,000-iteration
 * key/cert PBES2 and JDK 17 SUN cannot load it. Therefore production must not change the current
 * writer to this route while SUN interoperability is required; there is no winning BC 1.85 JCA
 * surface for the requested low-PBE .pfx.
 */
class Pkcs12PbeParamsSpikeTest {
    @Test
    fun `standard BC PKCS12 has fixed parameters and is readable by BC and SUN`() {
        val encoded = writeStandardStore()
        val params = parse(encoded)

        assertEquals(600_000, params.keyPbeIterations)
        assertEquals(600_000, params.certPbeIterations)
        assertEquals(1_200_000, params.macData.iterationCount.intValueExact())
        assertEquals(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, params.keyAlgorithm.algorithm)
        assertEquals(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, params.certAlgorithm.algorithm)
        assertEquals(ASN1ObjectIdentifier("1.3.14.3.2.26"), params.macData.mac.algorithmId.algorithm)

        assertPrivateKeyLoads(encoded, "BC")
        assertPrivateKeyLoads(encoded, "SUN")
    }

    @Test
    fun `PasswordProtection algorithms cannot configure BC PKCS12 entries`() {
        val acceptedBcCipherName = "PBEWithSHA256And256BitAES-CBC-BC"
        assertEquals("BC", Cipher.getInstance(acceptedBcCipherName, "BC").provider.name)

        val store = newBcKeyStore("PKCS12")
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        assertFailsWith<KeyStoreException> {
            store.setEntry(
                ALIAS,
                KeyStore.PrivateKeyEntry(keyPair.private, arrayOf(trustedCertificate())),
                KeyStore.PasswordProtection(
                    PASSWORD,
                    "PBEWithHmacSHA256AndAES_256",
                    PBEParameterSpec(ByteArray(16), LOW_ITERATIONS),
                ),
            )
        }
        assertFailsWith<KeyStoreException> {
            store.setEntry(
                ALIAS,
                KeyStore.PrivateKeyEntry(keyPair.private, arrayOf(trustedCertificate())),
                KeyStore.PasswordProtection(
                    PASSWORD,
                    acceptedBcCipherName,
                    PBEParameterSpec(ByteArray(16), LOW_ITERATIONS),
                ),
            )
        }
    }

    @Test
    fun `standard BC PKCS12 ignores store MAC parameter and JDK PKCS12 system properties`() {
        val requestedPbmac1 = PKCS12StoreParameter.pbmac1WithPBKDF2Builder()
            .setSalt(ByteArray(16) { 7 })
            .setIterationCount(LOW_ITERATIONS)
            .build()
        val parameterized = writeStandardStore(requestedPbmac1)
        assertStandardFixedParameters(parse(parameterized))

        withJdkPkcs12Properties(LOW_ITERATIONS) {
            val propertyConfigured = writeStandardStore()
            assertStandardFixedParameters(parse(propertyConfigured))
        }
    }

    @Test
    fun `PBMAC1 store parameter controls MAC only and breaks SUN interoperability`() {
        val encoded = writePbmac1Store()
        val params = parse(encoded)
        val pbmac1 = org.bouncycastle.asn1.pkcs.PBMAC1Params.getInstance(params.macData.mac.algorithmId.parameters)
        val pbkdf2 = PBKDF2Params.getInstance(pbmac1.keyDerivationFunc.parameters)

        assertEquals(PKCSObjectIdentifiers.id_PBMAC1, params.macData.mac.algorithmId.algorithm)
        assertEquals(LOW_ITERATIONS, pbkdf2.iterationCount.intValueExact())
        assertEquals(600_000, params.keyPbeIterations)
        assertEquals(600_000, params.certPbeIterations)
        assertEquals(PKCSObjectIdentifiers.id_PBES2, params.keyAlgorithm.algorithm)
        assertEquals(PKCSObjectIdentifiers.id_PBES2, params.certAlgorithm.algorithm)
        assertPrivateKeyLoads(encoded, "BC")
        assertFailsWith<java.io.IOException> { load(encoded, "SUN") }

        val standardLoadMillis = measureTimeMillis { load(writeStandardStore(), "BC") }
        val lowMacLoadMillis = measureTimeMillis { load(encoded, "BC") }
        println("BC PKCS12 load: standard=${standardLoadMillis}ms, PBMAC1-low-MAC=${lowMacLoadMillis}ms")
    }

    private fun assertStandardFixedParameters(params: ParsedPfx) {
        assertEquals(600_000, params.keyPbeIterations)
        assertEquals(600_000, params.certPbeIterations)
        assertEquals(1_200_000, params.macData.iterationCount.intValueExact())
        assertEquals(ASN1ObjectIdentifier("1.3.14.3.2.26"), params.macData.mac.algorithmId.algorithm)
    }

    private fun writeStandardStore(macAlgorithm: AlgorithmIdentifier? = null): ByteArray {
        val store = populatedStore("PKCS12")
        return ByteArrayOutputStream().also { output ->
            if (macAlgorithm == null) {
                store.store(output, PASSWORD)
            } else {
                store.store(PKCS12StoreParameter.builder(output, PASSWORD).setMacAlgorithm(macAlgorithm).build())
            }
        }.toByteArray()
    }

    private fun writePbmac1Store(): ByteArray {
        val store = populatedStore("PKCS12-PBMAC1")
        val macAlgorithm = PKCS12StoreParameter.pbmac1WithPBKDF2Builder()
            .setSalt(ByteArray(16) { 9 })
            .setIterationCount(LOW_ITERATIONS)
            .build()
        return ByteArrayOutputStream().also { output ->
            store.store(PKCS12StoreParameter.builder(output, PASSWORD).setMacAlgorithm(macAlgorithm).build())
        }.toByteArray()
    }

    private fun populatedStore(type: String): KeyStore = newBcKeyStore(type).apply {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        setKeyEntry(ALIAS, keyPair.private, PASSWORD, arrayOf(trustedCertificate()))
    }

    private fun newBcKeyStore(type: String): KeyStore = KeyStore.getInstance(type, "BC").apply {
        load(null, PASSWORD)
    }

    private fun trustedCertificate(): java.security.cert.Certificate {
        val cacerts = KeyStore.getInstance("JKS", "SUN").apply {
            FileInputStream("${System.getProperty("java.home")}/lib/security/cacerts").use { load(it, "changeit".toCharArray()) }
        }
        return CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(cacerts.getCertificate(cacerts.aliases().nextElement()).encoded),
        )
    }

    private fun assertPrivateKeyLoads(encoded: ByteArray, provider: String) {
        assertNotNull(load(encoded, provider).getKey(ALIAS, PASSWORD), "$provider must yield the private key")
    }

    private fun load(encoded: ByteArray, provider: String): KeyStore = KeyStore.getInstance("PKCS12", provider).apply {
        load(ByteArrayInputStream(encoded), PASSWORD)
    }

    private fun parse(encoded: ByteArray): ParsedPfx {
        val pfx = Pfx.getInstance(ASN1Primitive.fromByteArray(encoded))
        val authSafe = AuthenticatedSafe.getInstance(
            ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(pfx.authSafe.content).octets),
        )
        val keyContent = authSafe.contentInfo.single { it.contentType == PKCSObjectIdentifiers.data }
        val keyBags = ASN1Sequence.getInstance(ASN1OctetString.getInstance(keyContent.content).octets)
        val keyBag = SafeBag.getInstance(keyBags.getObjectAt(0))
        val keyAlgorithm = EncryptedPrivateKeyInfo.getInstance(keyBag.bagValue).encryptionAlgorithm
        val certContent = authSafe.contentInfo.single { it.contentType == PKCSObjectIdentifiers.encryptedData }
        val certAlgorithm = EncryptedData.getInstance(certContent.content).encryptionAlgorithm
        return ParsedPfx(
            keyAlgorithm = keyAlgorithm,
            certAlgorithm = certAlgorithm,
            macData = requireNotNull(pfx.macData),
            keyPbeIterations = pbeIterations(keyAlgorithm),
            certPbeIterations = pbeIterations(certAlgorithm),
        )
    }

    private fun pbeIterations(algorithm: AlgorithmIdentifier): Int = when (algorithm.algorithm) {
        PKCSObjectIdentifiers.id_PBES2 -> {
            val pbes2 = PBES2Parameters.getInstance(algorithm.parameters)
            PBKDF2Params.getInstance(pbes2.keyDerivationFunc.parameters).iterationCount.intValueExact()
        }

        else -> PKCS12PBEParams.getInstance(algorithm.parameters).iterations.intValueExact()
    }

    private inline fun withJdkPkcs12Properties(iterations: Int, block: () -> Unit) {
        val names = listOf(
            "keystore.pkcs12.macIterationCount",
            "keystore.pkcs12.certPbeIterationCount",
            "keystore.pkcs12.keyPbeIterationCount",
        )
        val previous = names.associateWith(System::getProperty)
        try {
            names.forEach { System.setProperty(it, iterations.toString()) }
            block()
        } finally {
            previous.forEach { (name, value) ->
                if (value == null) System.clearProperty(name) else System.setProperty(name, value)
            }
        }
    }

    private data class ParsedPfx(
        val keyAlgorithm: AlgorithmIdentifier,
        val certAlgorithm: AlgorithmIdentifier,
        val macData: MacData,
        val keyPbeIterations: Int,
        val certPbeIterations: Int,
    )

    private companion object {
        val PASSWORD = "not-a-secret".toCharArray()
        const val ALIAS = "identity"
        const val LOW_ITERATIONS = 2_048

        init {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
            Security.insertProviderAt(BouncyCastleProvider(), 1)
        }
    }
}

package ai.passman.keystore

import ai.passman.keystore.model.Keystore
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.nio.file.Files
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.Security
import java.security.cert.CertificateFactory
import kotlin.system.measureTimeMillis
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.DERBMPString
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.pkcs.AuthenticatedSafe
import org.bouncycastle.asn1.pkcs.EncryptedData
import org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo
import org.bouncycastle.asn1.pkcs.MacData
import org.bouncycastle.asn1.pkcs.PBES2Parameters
import org.bouncycastle.asn1.pkcs.PBKDF2Params
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.Pfx
import org.bouncycastle.asn1.pkcs.SafeBag
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.OutputEncryptor
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder

/**
 * Empirical BC 1.85/JDK 17 result: the bcpkix builder route is viable for a low-work-factor,
 * SUN-compatible PKCS#12. The production recipe is:
 *
 * 1. Create a `JcePKCSPBEOutputEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)`, bind it
 *    to BC, call `setIterationCount(2048)`, and call `setPRF(AlgorithmIdentifier(
 *    PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))` before `build(password)`.
 *    Use one such encryptor for the `JcaPKCS12SafeBagBuilder(privateKey, encryptor)` and another
 *    for `PKCS12PfxPduBuilder.addEncryptedData(encryptor, certificateBag)`. Passing the AES OID,
 *    not `id_PBES2`, is the important form: BC wraps it in PBES2/PBKDF2 itself.
 * 2. Build with `JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256).setProvider("BC")
 *    .setIterationCount(2048)`. This emits the classic PKCS#12 SHA-256 MAC (not PBMAC1), which
 *    both BC and JDK 17 SUN accept.
 * 3. Add equal `friendlyName` and `localKeyId` bag attributes to the key and leaf certificate so
 *    JCA providers associate the certificate with the private key.
 *
 * Re-save trap: loading this file into `KeyStore.getInstance("PKCS12", "BC")` and calling the
 * ordinary `store(output, password)` loses the requested profile. BC 1.85 rewrites the key to
 * legacy PKCS#12 3DES PBE and the cert to legacy 40-bit RC2 PBE, each at 600,000 iterations.
 * It preserves the loaded SHA-256 MAC's 2,048 count (a newly-created BC JCA store instead defaults
 * its MAC to SHA-1/1,200,000). A production writer must therefore preserve this builder route for
 * every mutation, never plain
 * `KeyStore.store` on an identity `.pfx`.
 *
 * Current identity-PFX `store()` call sites found by grep:
 * `JvmKeyStoreClient.createKeyStore` (initial empty file; reached by
 * `JvmKeystoreLifecycle.createKeystoreForUser`), `addKeystoreKey` (the second create-user write),
 * `deleteKeyStoreKey`, and `changeKeystorePassword` (replacement file). `JvmKeystoreLifecycle`
 * has no direct `store()` call; it delegates creation and password change to those methods.
 */
class Pkcs12LowPbeBuilderSpikeTest {
    @Test
    fun `PBES2 wrapper OID is not a usable encryptor input`() {
        assertFailsWith<org.bouncycastle.operator.OperatorCreationException> {
            JcePKCSPBEOutputEncryptorBuilder(PKCSObjectIdentifiers.id_PBES2)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setIterationCount(LOW_ITERATIONS)
                .setPRF(AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
                .build(PASSWORD)
        }
    }

    @Test
    fun `builder emits low PBES2 AES256 and SHA256 MAC readable by BC SUN and production path`() {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        val encoded = buildLowIterationPfx(keyPair)
        assertLowPbeProfile(parse(encoded))

        assertPrivateKeyLoads(encoded, "BC", keyPair)
        withBouncyCastleDemoted {
            assertPrivateKeyLoads(encoded, "SUN", keyPair)
        }

        val directory = Files.createTempDirectory("low-pbe-builder").toFile()
        try {
            val pfx = File(directory, "identity.pfx")
            pfx.writeBytes(encoded)
            val keystore = Keystore(directory.absolutePath, pfx.name, String(PASSWORD))
            val client = JvmKeyStoreClient()

            val loaded = client.getKeyStoreInfo(keystore).getOrThrow()
            assertEquals("SUN", loaded.provider.name, "production read path should prefer SUN")
            assertContentEquals(
                keyPair.private.encoded,
                assertNotNull(client.unwrapKey(loaded, ALIAS, PASSWORD)).encoded,
                "production unwrapKey must return the builder-written private key",
            )
        } finally {
            directory.deleteRecursively()
        }
    }

    @Test
    fun `BC KeyStore store rewrites builder PBE to fixed high defaults while retaining its MAC`() {
        val lowPbe = buildLowIterationPfx(KeyPairGenerator.getInstance("RSA").generateKeyPair())
        val defaultBc = writeStandardBcStore()
        val resaved = resaveWithBcKeyStore(lowPbe)

        val resavedParameters = parse(resaved)
        assertEquals(600_000, pbeIterations(resavedParameters.keyAlgorithm))
        assertEquals(600_000, pbeIterations(resavedParameters.certificateAlgorithm))
        assertEquals(LOW_ITERATIONS, resavedParameters.mac.iterationCount.intValueExact())
        assertEquals(NISTObjectIdentifiers.id_sha256, resavedParameters.mac.mac.algorithmId.algorithm)
        assertEquals(PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC, resavedParameters.keyAlgorithm.algorithm)
        assertEquals(PKCSObjectIdentifiers.pbeWithSHAAnd40BitRC2_CBC, resavedParameters.certificateAlgorithm.algorithm)

        val lowLoadMillis = measureTimeMillis { load(lowPbe, "BC") }
        val defaultLoadMillis = measureTimeMillis { load(defaultBc, "BC") }
        println("BC PKCS12 load: low-PBE=${lowLoadMillis}ms, BC-default=${defaultLoadMillis}ms")
    }

    private fun buildLowIterationPfx(keyPair: KeyPair): ByteArray {
        val localKeyId = DEROctetString(MessageDigest.getInstance("SHA-1").digest(keyPair.public.encoded))
        val keyBag = JcaPKCS12SafeBagBuilder(keyPair.private, lowPbeEncryptor()).apply {
            addIdentityAttributes(localKeyId)
        }.build()
        val certificateBag = JcaPKCS12SafeBagBuilder(trustedCertificate()).apply {
            addIdentityAttributes(localKeyId)
        }.build()

        return PKCS12PfxPduBuilder().apply {
            addData(keyBag)
            addEncryptedData(lowPbeEncryptor(), certificateBag)
        }.build(
            JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .setIterationCount(LOW_ITERATIONS),
            PASSWORD,
        ).encoded
    }

    private fun JcaPKCS12SafeBagBuilder.addIdentityAttributes(localKeyId: DEROctetString) {
        addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString(ALIAS))
        addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, localKeyId)
    }

    private fun lowPbeEncryptor(): OutputEncryptor = JcePKCSPBEOutputEncryptorBuilder(
        NISTObjectIdentifiers.id_aes256_CBC,
    ).setProvider(BouncyCastleProvider.PROVIDER_NAME)
        .setIterationCount(LOW_ITERATIONS)
        .setPRF(AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
        .build(PASSWORD)

    private fun writeStandardBcStore(): ByteArray {
        val keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair()
        return KeyStore.getInstance("PKCS12", "BC").apply {
            load(null, PASSWORD)
            setKeyEntry(ALIAS, keyPair.private, PASSWORD, arrayOf(trustedCertificate()))
        }.let { keyStore ->
            ByteArrayOutputStream().use { output ->
                keyStore.store(output, PASSWORD)
                output.toByteArray()
            }
        }
    }

    private fun resaveWithBcKeyStore(encoded: ByteArray): ByteArray {
        val keyStore = load(encoded, "BC")
        return ByteArrayOutputStream().use { output ->
            keyStore.store(output, PASSWORD)
            output.toByteArray()
        }
    }

    private fun assertPrivateKeyLoads(encoded: ByteArray, provider: String, expected: KeyPair) {
        assertContentEquals(
            expected.private.encoded,
            assertNotNull(load(encoded, provider).getKey(ALIAS, PASSWORD), "$provider must yield the private key").encoded,
        )
    }

    private fun load(encoded: ByteArray, provider: String): KeyStore = KeyStore.getInstance("PKCS12", provider).apply {
        load(ByteArrayInputStream(encoded), PASSWORD)
    }

    private fun withBouncyCastleDemoted(block: () -> Unit) {
        val present = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null
        if (present) Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        try {
            block()
        } finally {
            if (present && Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.insertProviderAt(BouncyCastleProvider(), 1)
            }
        }
    }

    private fun trustedCertificate(): java.security.cert.X509Certificate {
        val cacerts = KeyStore.getInstance("JKS", "SUN").apply {
            FileInputStream("${System.getProperty("java.home")}/lib/security/cacerts").use {
                load(it, "changeit".toCharArray())
            }
        }
        return CertificateFactory.getInstance("X.509").generateCertificate(
            ByteArrayInputStream(cacerts.getCertificate(cacerts.aliases().nextElement()).encoded),
        ) as java.security.cert.X509Certificate
    }

    private fun parse(encoded: ByteArray): ParsedPfx {
        val pfx = Pfx.getInstance(ASN1Primitive.fromByteArray(encoded))
        val authenticatedSafe = AuthenticatedSafe.getInstance(
            ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(pfx.authSafe.content).octets),
        )
        val keyContent = authenticatedSafe.contentInfo.single { it.contentType == PKCSObjectIdentifiers.data }
        val keyBags = ASN1Sequence.getInstance(ASN1OctetString.getInstance(keyContent.content).octets)
        val keyBag = SafeBag.getInstance(keyBags.getObjectAt(0))
        val keyAlgorithm = EncryptedPrivateKeyInfo.getInstance(keyBag.bagValue).encryptionAlgorithm
        val certificateContent = authenticatedSafe.contentInfo.single { it.contentType == PKCSObjectIdentifiers.encryptedData }
        val certificateAlgorithm = EncryptedData.getInstance(certificateContent.content).encryptionAlgorithm
        return ParsedPfx(
            keyAlgorithm = keyAlgorithm,
            certificateAlgorithm = certificateAlgorithm,
            mac = requireNotNull(pfx.macData),
        )
    }

    private fun parsePbes2(algorithm: AlgorithmIdentifier): Pbes2Profile {
        assertEquals(PKCSObjectIdentifiers.id_PBES2, algorithm.algorithm)
        val pbes2 = PBES2Parameters.getInstance(algorithm.parameters)
        assertEquals(PKCSObjectIdentifiers.id_PBKDF2, pbes2.keyDerivationFunc.algorithm)
        val pbkdf2 = PBKDF2Params.getInstance(pbes2.keyDerivationFunc.parameters)
        return Pbes2Profile(
            iterations = pbkdf2.iterationCount.intValueExact(),
            prf = pbkdf2.prf,
            encryptionScheme = pbes2.encryptionScheme.algorithm,
        )
    }

    private fun assertLowPbeProfile(profile: ParsedPfx) {
        listOf(profile.keyAlgorithm, profile.certificateAlgorithm).map(::parsePbes2).forEach { pbes2 ->
            assertEquals(LOW_ITERATIONS, pbes2.iterations)
            assertEquals(PKCSObjectIdentifiers.id_hmacWithSHA256, pbes2.prf.algorithm)
            assertEquals(NISTObjectIdentifiers.id_aes256_CBC, pbes2.encryptionScheme)
        }
        assertEquals(LOW_ITERATIONS, profile.mac.iterationCount.intValueExact())
        assertEquals(NISTObjectIdentifiers.id_sha256, profile.mac.mac.algorithmId.algorithm)
    }

    private data class ParsedPfx(
        val keyAlgorithm: AlgorithmIdentifier,
        val certificateAlgorithm: AlgorithmIdentifier,
        val mac: MacData,
    )

    private data class Pbes2Profile(
        val iterations: Int,
        val prf: AlgorithmIdentifier,
        val encryptionScheme: org.bouncycastle.asn1.ASN1ObjectIdentifier,
    )

    private fun pbeIterations(algorithm: AlgorithmIdentifier): Int = when (algorithm.algorithm) {
        PKCSObjectIdentifiers.id_PBES2 -> PBKDF2Params.getInstance(
            PBES2Parameters.getInstance(algorithm.parameters).keyDerivationFunc.parameters,
        ).iterationCount.intValueExact()

        else -> org.bouncycastle.asn1.pkcs.PKCS12PBEParams.getInstance(algorithm.parameters).iterations.intValueExact()
    }

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

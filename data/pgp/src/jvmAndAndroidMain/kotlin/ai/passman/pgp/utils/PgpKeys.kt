package ai.passman.pgp.utils

import ai.passman.keys.model.*
import ai.passman.logging.KLogger
import ai.passman.pgp.utils.PgpHelper.BOUNCY_PROVIDER
import java.io.*
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.util.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.bcpg.*
import org.bouncycastle.bcpg.sig.Features
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.crypto.digests.SHA512tDigest
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ElGamalParameterSpec
import org.bouncycastle.math.Primes
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.*
import org.bouncycastle.openpgp.operator.jcajce.*
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider


object PgpKeys {
    private const val SIG_HASH: Int = HashAlgorithmTags.SHA512

    /** Key-agreement algorithms: usable as an encryption subkey, never as a ring's primary. */
    private val ENCRYPTION_ONLY_ALGORITHMS = setOf<PGPKeyAlgo>(X25519, X448)

    /**
     * Algorithms whose primary key signs data itself rather than delegating to a signing subkey.
     * Every EdDSA family member works this way — one signing key is the point of the curve — and
     * ECDSA joins them because a separate ECDSA signing subkey buys nothing over the primary.
     */
    private val SELF_SIGNING_PRIMARIES = setOf<PGPKeyAlgo>(EDDSA, ED25519, ED448, ECDSA)

    /**
     * The NIST curve behind a requested key length. P-521 is offered as "521" because that is its
     * real field size; anything unrecognised lands on P-256, the curve the dropdown defaults to.
     */
    private fun curveForLength(length: Int): ECCurve = when (length) {
        384 -> ECCurve.NIST_P384
        521, 512 -> ECCurve.NIST_P521
        else -> ECCurve.NIST_P256
    }
    private val HASH_PREFERENCES = intArrayOf(
        HashAlgorithmTags.SHA512,
        HashAlgorithmTags.SHA384,
        HashAlgorithmTags.SHA256,
        HashAlgorithmTags.SHA224
    )
    // Advertised algorithm preferences on newly generated keys. Legacy CAST5/3DES entries dropped:
    // preferences are hints to senders, so removing them never breaks reading existing data — it
    // just stops inviting weak 64-bit block ciphers.
    private val SYM_PREFERENCES = intArrayOf(
        SymmetricKeyAlgorithmTags.AES_256,
        SymmetricKeyAlgorithmTags.AES_192,
        SymmetricKeyAlgorithmTags.AES_128
    )
    private val COMP_PREFERENCES = intArrayOf(
        CompressionAlgorithmTags.ZLIB,
        CompressionAlgorithmTags.BZIP2,
        CompressionAlgorithmTags.ZIP,
        CompressionAlgorithmTags.UNCOMPRESSED
    )

    init {
        Security.addProvider(BouncyCastleProvider())
        if (Security.getProvider("BCPQC") == null) {
            Security.addProvider(BouncyCastlePQCProvider())
        }
    }

    /**
     * [s2kCount] is the coded S2K octet (0x60 = 64KiB hashed, 0xff = ~65MB hashed). The default is
     * the maximum, and every ring this app creates takes it: a ring is sealed with a passphrase the
     * user typed, and a typed passphrase deserves every bit of stretching.
     *
     * The parameter exists for the opposite case — a passphrase generated at full entropy (24
     * characters over a 93-character alphabet is ~157 bits), against which the stretch factor is
     * irrelevant while on a phone the maximum costs seconds per key at ring creation and again at
     * every unlock. Nothing passes a low count today; provisioned rings were the only caller that
     * ever did, and the app no longer mints any. Anything that starts generating passphrases again
     * should pass 0x60 rather than pay for stretching that buys nothing.
     *
     * (A digest-provider swap is NOT a way out of the cost: iterated S2K feeds the digest a few
     * dozen bytes at a time, so a native digest drowns in per-call overhead and saves nothing.)
     */
    fun createSecretKeyEncryptor(password: CharArray, s2kCount: Int = 0xff): PBESecretKeyEncryptor {
        val sha256DigestCalculator = BcPGPDigestCalculatorProvider()[HashAlgorithmTags.SHA256]
        return BcPBESecretKeyEncryptorBuilder(
            PGPEncryptedData.AES_256,
            sha256DigestCalculator,
            s2kCount,
        ).build(password)
    }

    fun getSecretKeyRing(privateKeyRingBytes: ByteArray, password: String): PGPSecretKeyRing {
        // getDecoderStream auto-detects armored vs binary: imports copy files verbatim, so a
        // secret ring on disk is not guaranteed to be armored.
        val secretKeyRing = PGPUtil.getDecoderStream(ByteArrayInputStream(privateKeyRingBytes)).use {
            PGPObjectFactory(it, JcaKeyFingerprintCalculator()).nextObject() as PGPSecretKeyRing
        }
        // Test if we got the right password
        val decryptor = BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(password.toCharArray())
        secretKeyRing.secretKey.extractPrivateKey(decryptor)
        return secretKeyRing
    }

    fun getPublicKeyRing(publicKeyRingBytes: ByteArray): PGPPublicKeyRing {
        return ArmoredInputStream(ByteArrayInputStream(publicKeyRingBytes)).use {
            val pgpObjectFactory = PGPObjectFactory(it, JcaKeyFingerprintCalculator())
            pgpObjectFactory.nextObject() as PGPPublicKeyRing
        }
    }

    fun readPublicKey(publicKeyPath: String): PGPPublicKey {
        val bakey = FileInputStream(File(publicKeyPath)).use { inputStream ->
            PGPUtil.getDecoderStream(inputStream).readBytes()
        }

        // Refuse to encrypt to a ring carrying an algorithm this build cannot read, rather than
        // encrypting to whatever survived.
        //
        // The selection below walks what BouncyCastle hands back, and for a v4 ring BC drops a
        // subkey with an unknown algorithm *along with every subkey after it*, reporting the ring
        // as whole. So the key picked here could be an earlier subkey the peer has since moved off,
        // or the primary via the fallback path - and the peer may then be unable to decrypt what we
        // send, for a reason nothing on either side would explain.
        //
        // Guarding here rather than when the ring arrives is deliberate. Sync copies key files
        // byte-for-byte (DirectoryBundler.bundle does not re-encode), so a ring from a newer peer
        // round-trips losslessly and storing it costs nothing; refusing it at the door would block
        // the user's own key material and stop two devices converging. Holding the ring is safe.
        // Using it is not.
        val support = inspectKeyRingSupport(bakey)
        require(support !is PgpKeyRingSupport.UnsupportedAlgorithm) {
            "this key uses algorithm ${(support as PgpKeyRingSupport.UnsupportedAlgorithm).algorithmId}, " +
                "which this version cannot read; refusing to encrypt to it"
        }

        val objectFactory = PGPObjectFactory(bakey, BcKeyFingerprintCalculator())

        // Prefer a key whose usage flags explicitly allow encryption; fall back to any
        // encryption-capable key. The fallback matters for compatibility: the flag check was a
        // no-op for years (an `or`/`and` bug), so keys this app has been happily encrypting to —
        // e.g. master-only RSA keys carrying just the CERTIFY flag — must keep working. The flags
        // still decide *which* key wins when a ring has several candidates.
        var flagged: PGPPublicKey? = null
        var fallback: PGPPublicKey? = null
        fun consider(k: PGPPublicKey) {
            if (!k.isEncryptionKey) return
            if (flagged == null && checkKeyFlagsForEncryption(k)) flagged = k
            if (fallback == null) fallback = k
        }

        var o = objectFactory.nextObject()
        while (o != null) {
            when (o) {
                is PGPPublicKeyRing -> o.publicKeys.forEach(::consider)
                is PGPSecretKeyRing -> o.publicKeys.forEach(::consider)
                else -> Unit // unrelated PGP object; keep scanning
            }
            o = objectFactory.nextObject()
        }
        return requireNotNull(flagged ?: fallback) { "Can't find encryption key in key ring." }
    }

    fun readSecretKey(secretKeyPath: String): PGPSecretKey {
        val pgpSec = FileInputStream(File(secretKeyPath)).use { inputStream ->
            PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(inputStream),
                BcKeyFingerprintCalculator()
            )
        }

        // we just loop through the collection till we find a key suitable for encryption, in the real
        // world you would probably want to be a bit smarter about this.
        val keyRingIter: Iterator<*> = pgpSec.keyRings
        while (keyRingIter.hasNext()) {
            val keyRing: PGPSecretKeyRing = keyRingIter.next() as PGPSecretKeyRing
            val keyIter: Iterator<*> = keyRing.secretKeys
            while (keyIter.hasNext()) {
                val key: PGPSecretKey = keyIter.next() as PGPSecretKey
                if (key.isSigningKey) {
                    return key
                }
            }
        }
        throw IllegalArgumentException("Can't find signing key in key ring.")
    }

    private fun checkKeyFlagsForEncryption(key: PGPPublicKey): Boolean {
        // If Key Usage flags are present, we must respect them:
        var keyFlagsEncountered = 0
        var keyUsageAllowsEncryption = false

        val i: Iterator<PGPSignature> = key.signatures
        while (i.hasNext()) {
            val signature = i.next()
            val keyFlags = signature.hashedSubPackets.keyFlags
            keyFlagsEncountered += keyFlags
            // Test whether the bit is SET: (flags AND MASK) != 0. The old code used `or`, which is
            // always > 0 for a positive mask, so the usage check silently passed every key.
            val isEncryptComms = keyFlags and KeyFlags.ENCRYPT_COMMS > 0
            val isEncryptStorage = keyFlags and KeyFlags.ENCRYPT_STORAGE > 0
            // Other KeyFlags available here (AUTHENTICATION, SIGN_DATA, CERTIFY_OTHER).
            if (isEncryptComms || isEncryptStorage) {
                keyUsageAllowsEncryption = true
            }
        }

        // However, if Key Usage flags are not present (older key, or key generation process simply did not include the flags)
        // then we still attempt to use an encryption key using the existing methods:
        keyUsageAllowsEncryption = keyFlagsEncountered == 0 || keyUsageAllowsEncryption
        return keyUsageAllowsEncryption
    }

    fun getPrivateKey(secretKey: PGPSecretKey, password: String): PGPPrivateKey =
        secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider())
                .build(password.toCharArray())
        )

    fun findSecretKey(secretKeyRing: PGPSecretKeyRing, keyID: Long, passphrase: String): PGPPrivateKey? {
        val secretKey = secretKeyRing.getSecretKey(keyID)
        return secretKey?.extractPrivateKey(
            JcePBESecretKeyDecryptorBuilder().setProvider(BOUNCY_PROVIDER).build(passphrase.toCharArray())
        )
    }

    fun findSecretKey(secretKeyStream: InputStream, keyID: Long, pass: CharArray): PGPPrivateKey? {
        // val privateKeyStream = FileInputStream(File(privateKeyPath))
        val pgpSec = PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(secretKeyStream), BcKeyFingerprintCalculator())
        val pgpSecKey: PGPSecretKey = pgpSec.getSecretKey(keyID) ?: return null
        val keyDecryptor: PBESecretKeyDecryptor =
            JcePBESecretKeyDecryptorBuilder(
                JcaPGPDigestCalculatorProviderBuilder()
                    .setProvider(BOUNCY_PROVIDER)
                    .build()
            ).setProvider(BOUNCY_PROVIDER).build(pass)
        return pgpSecKey.extractPrivateKey(keyDecryptor)
    }

    fun getSecretSignKeyFromCollection(input: InputStream?): PGPSecretKey? {
        val secretKeyRinCollection = PGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(input),
            BcKeyFingerprintCalculator()
        )

        secretKeyRinCollection.keyRings.forEach { secretKeyRing ->
            secretKeyRing.secretKeys.forEach {
                if (it.isSigningKey) {
                    return it
                }
            }
        }

         return null
    }

    fun findPublicKeyById(path: String, keyID: Long): PGPPublicKey? {
        val bytes = FileInputStream(File(path)).use { fis ->
            PGPUtil.getDecoderStream(fis).use { ds ->
                val baos = ByteArrayOutputStream()
                ds.copyTo(baos)
                baos.toByteArray()
            }
        }
        val factory = PGPObjectFactory(bytes, JcaKeyFingerprintCalculator())
        var o = factory.nextObject()
        while (o != null) {
            when (o) {
                is PGPPublicKeyRing -> o.getPublicKey(keyID)?.let { return it }
                is PGPSecretKeyRing -> o.getPublicKey(keyID)?.let { return it }
                is PGPPublicKeyRingCollection -> o.getPublicKey(keyID)?.let { return it }
                is PGPSecretKeyRingCollection -> {
                    for (ring in o.keyRings) {
                        (ring as PGPSecretKeyRing).getPublicKey(keyID)?.let { return it }
                    }
                }
            }
            o = factory.nextObject()
        }
        return null
    }

    fun loadPublicKeys(path: String): PGPPublicKeyRingCollection {
        FileInputStream(path).use { fis ->
            ArmoredInputStream(fis).use { ais ->
                return PGPPublicKeyRingCollection(ais, JcaKeyFingerprintCalculator())
            }
        }
    }

    fun loadSecretKeys(path: String): PGPSecretKeyRingCollection {
        FileInputStream(path).use { fis ->
            ArmoredInputStream(fis).use { ais ->
                return PGPSecretKeyRingCollection(ais, JcaKeyFingerprintCalculator())
            }
        }
    }

    fun loadPublicKeyRing(path: String): PGPPublicKeyRing {
        FileInputStream(path).use { fis ->
            return PGPPublicKeyRing(PGPUtil.getDecoderStream(fis), JcaKeyFingerprintCalculator())
        }
    }

    fun loadSecretKeyRing(path: String): PGPSecretKeyRing {
        FileInputStream(path).use { fis ->
            return PGPSecretKeyRing(PGPUtil.getDecoderStream(fis), JcaKeyFingerprintCalculator())
        }
    }

    fun getSecretSignKeyFromRing(secretKeyRing: PGPSecretKeyRing): PGPSecretKey? {
        secretKeyRing.secretKeys.forEach {
            if (it.isSigningKey) {
                return it
            }
        }

        return null
    }

    fun getPublicEncryptKeyFromRing(secretKeyRing: PGPSecretKeyRing): PGPPublicKey? {
        secretKeyRing.publicKeys.forEach {
            if (it.isEncryptionKey) {
                return it
            }
        }

        return null
    }

    fun getMasterPublicKeyFromKeyRing(publicKeyRing: PGPPublicKeyRing): PGPPublicKey? {
        publicKeyRing.publicKeys.forEach { key ->
            if (key.isMasterKey) {
                return key
            }
        }
        return null
    }

    fun exportPublicKeyAsAsciiArmored(publicKey: PGPPublicKey): String {
        val byteArrayOutputStream = ByteArrayOutputStream()
        val armoredOutputStream = ArmoredOutputStream(byteArrayOutputStream)

        publicKey.encode(armoredOutputStream)

        armoredOutputStream.close()

        return byteArrayOutputStream.toString()
    }


    fun exportSecretKeyAsAsciiArmored(secretKey: PGPSecretKey): String {
        val byteArrayOutputStream = ByteArrayOutputStream()
        val armoredOutputStream = ArmoredOutputStream(byteArrayOutputStream)

        secretKey.encode(armoredOutputStream)

        armoredOutputStream.close()

        return byteArrayOutputStream.toString()
    }

    fun exportSecretKeyAsAsciiArmored(bytes: ByteArray): String {
        val byteArrayOutputStream = ByteArrayOutputStream()
        val armoredOutputStream = ArmoredOutputStream(byteArrayOutputStream)
        armoredOutputStream.write(bytes)
        armoredOutputStream.close()
        return byteArrayOutputStream.toString()
    }

    fun saveSecretKeyRingToFile(secretKeyRing: PGPSecretKeyRing, filename: String) {
        FileOutputStream(filename).use { fos ->
            ArmoredOutputStream(fos).use { armorOut ->
                secretKeyRing.encode(armorOut)
            }
        }
    }

    fun savePublicKeyRingToFile(publicKeyRing: PGPPublicKeyRing, filename: String) {
        FileOutputStream(filename).use { fos ->
            ArmoredOutputStream(fos).use { armorOut ->
                publicKeyRing.encode(armorOut)
            }
        }
    }

    fun createPgpKeyRingGenerator(
        userId: String,
        algorithm: PGPKeyAlgo,
        length: Int,
        expirationInSeconds: Long,
        password: String,
        s2kCount: Int = 0xff,
    ): PGPKeyRingGenerator {
        // bcpg only supports SHA-1 for the secret-key checksum; the S2K digest is SHA-256.
        val sha1Calc = BcPGPDigestCalculatorProvider()[HashAlgorithmTags.SHA1]

        val secretKeyEncryptor = createSecretKeyEncryptor(password.toCharArray(), s2kCount)

        // An encryption-only algorithm cannot carry a ring: there would be nothing to certify the
        // user id with. Those algorithms are valid as the *subkey* each branch below pairs in.
        require(algorithm !in ENCRYPTION_ONLY_ALGORITHMS) {
            "$algorithm is an encryption algorithm and cannot be a ring's primary key"
        }

        val primaryAlgo = when (algorithm) {
            DSA -> DSA
            ECDH -> ECDSA
            ECDSA -> ECDSA
            EDDSA -> EDDSA
            ED25519 -> ED25519
            ED448 -> ED448
            ELGAMAL -> DSA
            RSA -> RSA
            X25519 -> X25519
            X448 -> X448
        }

        val signAlgo = when (algorithm) {
            DSA -> ELGAMAL
            ECDH -> ECDSA
            ECDSA -> ECDSA
            EDDSA -> EDDSA
            ED25519 -> ED25519
            ED448 -> ED448
            ELGAMAL -> ELGAMAL
            RSA -> RSA
            X25519 -> X25519
            X448 -> X448
        }

        val encryptAlgo = when (algorithm) {
            DSA -> ELGAMAL
            ECDH -> ECDH
            ECDSA -> ECDH
            EDDSA -> ECDH
            ED25519 -> X25519
            ED448 -> X448
            ELGAMAL -> ELGAMAL // doesn't matter
            RSA -> RSA
            X25519 -> X25519
            X448 -> X448
        }

        // NIST EC is the only family here whose size is still a choice, and the UI expresses that
        // as the same "length" dropdown every other algorithm uses. Map it to a curve rather than
        // threading a second parameter through every caller for one algorithm's benefit.
        val curve = if (algorithm == ECDSA || algorithm == ECDH) curveForLength(length) else null

        // The primary key and its subkeys are independent, and at RSA-4096 each costs seconds of
        // CPU, so they are generated concurrently. runBlocking is acceptable behind this
        // synchronous API: the keygens run on Dispatchers.Default, the blocked caller thread does
        // none of the work.
        val (primaryKey, encryptionKey, signingKey) = runBlocking {
            val primary = async(Dispatchers.Default) { createKeyPair(length, primaryAlgo, curve) }
            val encryption = if (algorithm != DSA) {
                async(Dispatchers.Default) { createKeyPair(length, encryptAlgo, curve) }
            } else {
                null
            }
            val signing = if (algorithm != ELGAMAL && algorithm !in SELF_SIGNING_PRIMARIES) {
                async(Dispatchers.Default) { createKeyPair(length, signAlgo, curve) }
            } else {
                null
            }
            Triple(primary.await(), encryption?.await(), signing?.await())
        }
        val primarySubpackets = PGPSignatureSubpacketGenerator()
        primarySubpackets.setKeyFlags(
            true,
            KeyFlags.CERTIFY_OTHER or (if (algorithm in SELF_SIGNING_PRIMARIES) KeyFlags.SIGN_DATA else 0),
        )
        primarySubpackets.setPreferredHashAlgorithms(false, HASH_PREFERENCES)
        primarySubpackets.setPreferredSymmetricAlgorithms(false, SYM_PREFERENCES)
        primarySubpackets.setPreferredCompressionAlgorithms(false, COMP_PREFERENCES)
        primarySubpackets.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION)
        primarySubpackets.setIssuerFingerprint(false, primaryKey.publicKey)

        if (expirationInSeconds > 0) {
            primarySubpackets.setKeyExpirationTime(false, expirationInSeconds)
        }

        val contentSignerBuilder = certificationSignerBuilder(primaryKey.publicKey.algorithm)

        val gen = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primaryKey,
            userId,
            sha1Calc,
            primarySubpackets.generate(),
            null,
            contentSignerBuilder,
            secretKeyEncryptor,
        )

        if (encryptionKey != null) {
            val encryptionKeySubpackets = PGPSignatureSubpacketGenerator()
            encryptionKeySubpackets.setKeyFlags(true, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
            encryptionKeySubpackets.setIssuerFingerprint(false, primaryKey.publicKey)
            gen.addSubKey(encryptionKey, encryptionKeySubpackets.generate(), null)
        }

        if (signingKey != null) {
            val signingKeySubpacket = PGPSignatureSubpacketGenerator()
            signingKeySubpacket.setKeyFlags(true, KeyFlags.SIGN_DATA)
            signingKeySubpacket.setIssuerFingerprint(false, primaryKey.publicKey)
            gen.addSubKey(signingKey, signingKeySubpacket.generate(), null, contentSignerBuilder)
        }

        return gen
    }

    fun addNewKeyPairToSecretRing(
        existingRing: PGPSecretKeyRing,
        newKeyPair: PGPKeyPair,
        userID: String,
        passphrase: CharArray,
    ): PGPSecretKeyRing {
        // bcpg only supports SHA-1 for the secret-key checksum; the S2K digest is SHA-256.
        val sha1Calc = BcPGPDigestCalculatorProvider()[HashAlgorithmTags.SHA1]

        val contentSignerBuilder =
            JcaPGPContentSignerBuilder(newKeyPair.publicKey.algorithm, HashAlgorithmTags.SHA512)

        val secretKeyEncryptor = createSecretKeyEncryptor(passphrase)

        val newSecretKey = PGPSecretKey(
            PGPSignature.POSITIVE_CERTIFICATION,
            newKeyPair,
            userID,
            sha1Calc,
            null,
            null,
            contentSignerBuilder,
            secretKeyEncryptor
        )

        return PGPSecretKeyRing.insertSecretKey(existingRing, newSecretKey)
    }

    fun addPublicKeyToRing(
        existingRing: PGPPublicKeyRing,
        pgpKeyPair: PGPKeyPair,
    ): PGPPublicKeyRing {
        val newPublicKey = pgpKeyPair.publicKey
        return PGPPublicKeyRing.insertPublicKey(existingRing, newPublicKey)
    }

    /**
     * Conscrypt ("AndroidOpenSSL") runs RSA keygen natively in BoringSSL, several times faster
     * than BouncyCastle's Java implementation. The generated KeyPair is provider-neutral —
     * [JcaPGPKeyPair] only reads the standard RSA key interfaces — so only speed changes. Where
     * Conscrypt is absent (desktop), BC stays the generator.
     */
    private fun rsaKeyPairGenerator(): KeyPairGenerator =
        Security.getProvider("AndroidOpenSSL")
            ?.let { KeyPairGenerator.getInstance("RSA", it) }
            ?: KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME)

    /**
     * The signer for a new ring's certification signatures. The signature bytes are identical
     * whichever provider computes them; Conscrypt just does the RSA private-key math natively,
     * where BC's Java implementation costs hundreds of milliseconds per RSA-4096 signature on a
     * phone. Restricted to RSA because that is the only algorithm Conscrypt is guaranteed to sign
     * ([JcaPGPKeyPair] keeps the original Conscrypt key, so the JCA signer uses it directly);
     * everything else keeps the BC signer it always had.
     */
    private fun certificationSignerBuilder(keyAlgorithm: Int): PGPContentSignerBuilder {
        val conscrypt = Security.getProvider("AndroidOpenSSL")
        return if (conscrypt != null &&
            (keyAlgorithm == PGPPublicKey.RSA_GENERAL || keyAlgorithm == PGPPublicKey.RSA_SIGN)
        ) {
            JcaPGPContentSignerBuilder(keyAlgorithm, SIG_HASH).setProvider(conscrypt)
        } else {
            BcPGPContentSignerBuilder(keyAlgorithm, SIG_HASH)
        }
    }

    fun createKeyPair(keySize:Int, keyAlgorithm: PGPKeyAlgo, curve: ECCurve? = null): PGPKeyPair {
        require(keyAlgorithm != ECDSA || curve != null) { "ECDSA needs a curve" }

        val algorithm: Int
        val keyGen: KeyPairGenerator

        when (keyAlgorithm) {
            RSA -> {
                keyGen = rsaKeyPairGenerator()
                keyGen.initialize(keySize, SecureRandom())
                algorithm = PGPPublicKey.RSA_GENERAL
            }

            DSA -> {
                keyGen = KeyPairGenerator.getInstance(
                    "DSA",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                keyGen.initialize(keySize, SecureRandom())
                algorithm = PGPPublicKey.DSA
            }

            ELGAMAL -> {
                keyGen = KeyPairGenerator.getInstance(
                    "ElGamal",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                val p = Primes.generateSTRandomPrime(
                    SHA512tDigest(256),
                    keySize,
                    SecureRandom().generateSeed(keySize/2)
                ).prime
                val g = BigInteger("2")
                val elParams = ElGamalParameterSpec(p, g)
                keyGen.initialize(elParams)
                algorithm = PGPPublicKey.ELGAMAL_ENCRYPT
            }

            ECDSA -> {
                val ecParamSpec = when (curve!!) {
                    ECCurve.NIST_P256 -> ECGenParameterSpec("P-256")
                    ECCurve.NIST_P384 -> ECGenParameterSpec("P-384")
                    ECCurve.NIST_P521 -> ECGenParameterSpec("P-521")
                    ECCurve.Secp256k1 -> ECGenParameterSpec("secp256k1")
                }
                keyGen = KeyPairGenerator.getInstance(
                    "ECDSA",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                keyGen.initialize(ecParamSpec, SecureRandom())
                algorithm = PGPPublicKey.ECDSA
            }

            ECDH -> {
                if (curve == null) {
                    keyGen = KeyPairGenerator.getInstance(
                        "X25519",
                        BouncyCastleProvider.PROVIDER_NAME,
                    )
                } else {
                    val ecParamSpec = when (curve) {
                        ECCurve.NIST_P256 -> ECGenParameterSpec("P-256")
                        ECCurve.NIST_P384 -> ECGenParameterSpec("P-384")
                        ECCurve.NIST_P521 -> ECGenParameterSpec("P-521")
                        ECCurve.Secp256k1 -> ECGenParameterSpec("secp256k1")
                    }
                    keyGen = KeyPairGenerator.getInstance(
                        "ECDH",
                        BouncyCastleProvider.PROVIDER_NAME,
                    )
                    keyGen.initialize(ecParamSpec, SecureRandom())
                }
                algorithm = PublicKeyAlgorithmTags.ECDH
            }

            EDDSA -> {
                keyGen = KeyPairGenerator.getInstance(
                    "Ed25519",
                    BouncyCastleProvider.PROVIDER_NAME
                )
                algorithm = PublicKeyAlgorithmTags.EDDSA_LEGACY
            }

            // The RFC 9580 codepoints. Same underlying curves as the legacy pair above, but each
            // algorithm carries its own tag instead of riding on EdDSA/ECDH with a curve OID
            // inside. No initialize() call: the curve IS the algorithm, so there is no size or
            // parameter to pick, and passing one throws.
            ED25519 -> {
                keyGen = KeyPairGenerator.getInstance("Ed25519", BouncyCastleProvider.PROVIDER_NAME)
                algorithm = PublicKeyAlgorithmTags.Ed25519
            }

            X25519 -> {
                keyGen = KeyPairGenerator.getInstance("X25519", BouncyCastleProvider.PROVIDER_NAME)
                algorithm = PublicKeyAlgorithmTags.X25519
            }

            ED448 -> {
                keyGen = KeyPairGenerator.getInstance("Ed448", BouncyCastleProvider.PROVIDER_NAME)
                algorithm = PublicKeyAlgorithmTags.Ed448
            }

            X448 -> {
                keyGen = KeyPairGenerator.getInstance("X448", BouncyCastleProvider.PROVIDER_NAME)
                algorithm = PublicKeyAlgorithmTags.X448
            }
        }

        val started = System.currentTimeMillis()
        val generated = keyGen.genKeyPair()
        KLogger.d {
            "createKeyPair: $keyAlgorithm/$keySize via ${keyGen.provider.name} " +
                "took ${System.currentTimeMillis() - started}ms"
        }

        return JcaPGPKeyPair(PublicKeyPacket.VERSION_4, algorithm, generated, Date())
    }


}

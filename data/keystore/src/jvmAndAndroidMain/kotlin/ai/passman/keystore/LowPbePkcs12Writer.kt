package ai.passman.keystore

import ai.passman.logging.KLogger
import java.io.File
import java.math.BigInteger
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Provider
import java.security.Security
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1ObjectIdentifier
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
import org.bouncycastle.asn1.pkcs.PBES2Parameters
import org.bouncycastle.asn1.pkcs.PBKDF2Params
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.pkcs.Pfx
import org.bouncycastle.asn1.pkcs.SafeBag
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.OutputEncryptor
import org.bouncycastle.pkcs.PKCS12SafeBag
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder

/**
 * Writes a PKCS#12 whose password-based work factor is deliberately negligible, and recognises a
 * store that still carries an expensive one.
 *
 * ## When this is allowed, and when it is a vulnerability
 *
 * PBE iteration counts exist to make *guessing the password* expensive. The account identity store
 * is sealed with [ai.passman.crypto.vault.VaultCipher.identityStorePassword] — 256 bits of HKDF
 * output from the device master key, base64-encoded. There is no guessing attack against a uniformly
 * random 256-bit password at any iteration count, so every iteration above the minimum buys exactly
 * nothing and costs the user a second of login on a phone. That is the whole argument, and it is
 * conditional: **[ITERATIONS] is only defensible for a store whose password is that derived value.**
 *
 * For a store sealed with anything a human typed — every keystore the keystore-tools UI creates —
 * this class is a downgrade attack in library form. Nothing in `data:repo` calls it; the only callers
 * are [JvmKeyStoreClient]'s three `...IdentityKeyStore` methods, which exist solely to serve
 * `JvmKeystoreLifecycle`, which owns the `.pfx` and nothing else. Keep it that way: if a call site
 * ever appears where the password could be a login password, the iteration count is wrong for it.
 *
 * ## The recipe
 *
 * Proven in `Pkcs12LowPbeBuilderSpikeTest` against BC 1.85 / JDK 17: PBES2 with PBKDF2-HmacSHA256 and
 * AES-256-CBC at [ITERATIONS] for the shrouded key bags and for the certificate `encryptedData`, and
 * the classic PKCS#12 SHA-256 MAC (not PBMAC1) at [ITERATIONS]. Readable by BouncyCastle, by stock
 * SUN, and by the production [JvmKeyStoreClient.getKeyStoreInfo] / [JvmKeyStoreClient.unwrapKey]
 * path.
 *
 * Passing `NISTObjectIdentifiers.id_aes256_CBC` — not `id_PBES2` — to the encryptor builder is the
 * important form: BC wraps it in PBES2/PBKDF2 itself, and handing it the PBES2 wrapper OID instead
 * throws.
 *
 * ## The re-save trap
 *
 * Loading one of these files into a `KeyStore` and calling the ordinary `store()` throws the profile
 * away: BC 1.85 rewrites the key bag to legacy PKCS#12 3DES and the certificates to 40-bit RC2, both
 * at 600,000 iterations (it does preserve the loaded MAC's count). So every mutation of an identity
 * store has to come back through [encode]; a plain `store()` on a `.pfx` silently undoes this.
 */
object LowPbePkcs12Writer {

    /**
     * The PBKDF2 and MAC iteration count for identity stores.
     *
     * Not a tuning knob. It is low **because the password it protects is a 256-bit uniformly random
     * value from the device keyring**, which no work factor can help and no work factor is needed
     * for. Raising it would only make login slower; lowering it changes nothing either. Using this
     * class with a human-chosen password is what would make the number wrong, and no argument about
     * the number itself fixes that.
     */
    const val ITERATIONS = 2_048

    /**
     * Above this, a store's parameters are worth rewriting.
     *
     * Chosen to sit exactly on JDK 17's SUN defaults (10,000 for keys, certificates and the MAC) so a
     * SUN-written store is left alone, while BouncyCastle's (600,000 for the bags, 1,200,000 for a
     * freshly created MAC) is not. A store that is already at or below the SUN default costs little
     * enough to open that rewriting it would be churn.
     */
    private const val LEGACY_ITERATION_THRESHOLD = 10_000

    /**
     * The largest file [hasLegacyPbe] and [isStructurallyPkcs12] will read into memory.
     *
     * An identity store is one RSA key and one self-signed certificate: a few kilobytes, and the
     * largest thing that could legitimately grow it is a certificate chain. Four mebibytes is three
     * orders of magnitude of headroom and still small enough that a corrupt, hostile or simply
     * wrong file at this path cannot be turned into an allocation the login path pays for.
     *
     * Over the cap is answered "not legacy" with a warning, never an exception: these are consulted
     * during login, and the only safe reading for a file this cannot vouch for is "leave it alone".
     */
    private const val MAX_SNIFF_BYTES = 4L * 1024 * 1024

    /**
     * A private provider instance rather than the registered `"BC"` name.
     *
     * [encode] has to read key material out of a SUN-flavoured `KeyStore`, which requires BouncyCastle
     * to be *out* of the global provider list for the duration (see [withBouncyCastleDemoted]), and
     * then immediately build with BouncyCastle. Resolving the provider by name would make the second
     * half depend on the global state the first half mutates.
     */
    private val bouncyCastle: Provider = BouncyCastleProvider()

    /**
     * Oracle's `trustedKeyUsage` bag attribute, and the `anyExtendedKeyUsage` value SUN itself writes
     * for `setCertificateEntry`. A certificate-only bag without it is read back by SUN as chain
     * material rather than as a trusted-certificate entry, i.e. the alias would disappear.
     */
    private val TRUSTED_KEY_USAGE = ASN1ObjectIdentifier("2.16.840.1.113894.746875.1.1")
    private val ANY_EXTENDED_KEY_USAGE = ASN1ObjectIdentifier("2.5.29.37.0")

    /**
     * Re-encode every entry of [keyStore] into low-PBE PKCS#12 bytes sealed with [password].
     *
     * [password] must be the keyring-derived store password — see the class KDoc. It is used both to
     * read the existing entries and to seal the new ones.
     */
    fun encode(keyStore: KeyStore, password: CharArray): ByteArray = encode(keyStore, password, password)

    /**
     * Re-encode every entry of [keyStore], read with [readPassword], sealed under [writePassword].
     *
     * The two-password form is what a password change uses: it goes straight from the loaded store to
     * the new file, so there is no intermediate `KeyStore` for a stray `store()` to write at the wrong
     * parameters, and no in-memory copy of the entries beyond the ones this call holds.
     *
     * [writePassword] must be the keyring-derived store password — see the class KDoc.
     *
     * Every entry survives: private keys with their full certificate chain, and certificate-only
     * entries. Aliases are preserved exactly as [keyStore] reports them. An entry this cannot
     * represent (a secret key, a key with no chain, a non-X.509 certificate) throws rather than being
     * dropped — losing an entry silently is the failure mode this whole area is built to avoid.
     */
    fun encode(keyStore: KeyStore, readPassword: CharArray, writePassword: CharArray): ByteArray {
        // Reading a SUN-loaded key bag while BouncyCastle sits at provider position 1 resolves BC's
        // PBE implementation for a SUN-written bag and fails with "Given final block not properly
        // padded" — the same hazard JvmKeyStoreClient.unwrapKey demotes for. The demotion has to be
        // finished before the build below, which needs BouncyCastle.
        val entries = withProviderMatching(keyStore) { readEntries(keyStore, readPassword) }
        return build(entries, writePassword)
    }

    /**
     * Encode a single freshly generated key pair — [privateKey] and its self-signed [chain] — as a
     * low-PBE PKCS#12 sealed with [password], under [alias].
     *
     * What account creation needs, and it deliberately never materialises a `KeyStore`: a JCA store
     * would encrypt the key once at the provider's own parameters on `setKeyEntry` and again on
     * `store()`, and one stray `store()` on it is the re-save trap in the class KDoc.
     *
     * [password] must be the keyring-derived store password — see the class KDoc.
     */
    fun encode(alias: String, privateKey: PrivateKey, chain: List<X509Certificate>, password: CharArray): ByteArray {
        require(chain.isNotEmpty()) { "a PKCS#12 key entry needs at least its own certificate" }
        return build(listOf(KeyEntry(alias, privateKey, chain)), password)
    }

    /**
     * Does [pfxBytes] carry expensive password-based parameters?
     *
     * A parameter sniff, not a decryption: it walks the `AuthenticatedSafe` and reads the algorithm
     * identifiers, so it runs no PBE and needs no password. True means one of
     *
     * - a bag encrypted under the legacy PKCS#12 PBE family (3DES / RC2 / RC4, `1.2.840.113549.1.12.1.*`),
     *   which BouncyCastle writes at 600,000 iterations and which is SHA-1 based;
     * - a PBES2 bag whose PBKDF2 count is above [LEGACY_ITERATION_THRESHOLD];
     * - a file MAC above [LEGACY_ITERATION_THRESHOLD] (BouncyCastle's fresh-store default is
     *   SHA-1 at 1,200,000, and the MAC is paid on every open just like the bags are).
     *
     * **A parse failure is false.** This is consulted on the login path to decide whether to rewrite a
     * file; the only safe answer for bytes it cannot understand is "leave it alone".
     */
    fun hasLegacyPbe(pfxBytes: ByteArray): Boolean = runCatching { sniff(pfxBytes) }.getOrDefault(false)

    /**
     * [hasLegacyPbe] for a file, with the read bounded by [MAX_SNIFF_BYTES].
     *
     * The bounded overload is the one the login path uses. `File.readBytes` on an identity store is a
     * few kilobytes; on whatever else may have ended up at that path it is an unbounded allocation
     * driven by a file this code does not control, taken while the user is waiting to log in.
     */
    fun hasLegacyPbe(pfxFile: File): Boolean = readForSniff(pfxFile)?.let(::hasLegacyPbe) ?: false

    /**
     * Are [pfxFile]'s bytes a PKCS#12 structure at all?
     *
     * No password and no PBE: it parses the outer `Pfx` and stops. The question it answers for
     * [JvmKeyStoreClient.restoreIdentityKeyStoreFromBackup] is the one that separates "this store is
     * damaged" from "this store does not open with the password I happen to be holding", and only the
     * first of those justifies restoring a backup over it.
     *
     * A file over [MAX_SNIFF_BYTES] is `true` — the conservative answer here, since true is what
     * *prevents* the overwrite.
     */
    fun isStructurallyPkcs12(pfxFile: File): Boolean {
        val bytes = readForSniff(pfxFile) ?: return pfxFile.isFile
        return runCatching { Pfx.getInstance(ASN1Primitive.fromByteArray(bytes)) != null }.getOrDefault(false)
    }

    /** [file]'s bytes, or null when it is absent or larger than a sniff is allowed to read. */
    private fun readForSniff(file: File): ByteArray? {
        if (!file.isFile) return null
        val length = file.length()
        if (length > MAX_SNIFF_BYTES) {
            KLogger.w {
                "${file.name} is $length bytes, over the ${MAX_SNIFF_BYTES}-byte sniff cap; not reading it. " +
                    "An identity store is a few KiB, so this is not one."
            }
            return null
        }
        return runCatching { file.readBytes() }.getOrNull()
    }

    // ------------------------------------------------------------------ reading

    private sealed interface Pkcs12Entry {
        val alias: String
    }

    private class KeyEntry(
        override val alias: String,
        val privateKey: PrivateKey,
        val chain: List<X509Certificate>,
    ) : Pkcs12Entry

    private class CertificateEntry(
        override val alias: String,
        val certificate: X509Certificate,
    ) : Pkcs12Entry

    private fun readEntries(keyStore: KeyStore, password: CharArray): List<Pkcs12Entry> =
        keyStore.aliases().toList().map { alias ->
            when {
                keyStore.isKeyEntry(alias) -> {
                    val key = keyStore.getKey(alias, password)
                        ?: error("no key material under '$alias'")
                    val privateKey = key as? PrivateKey
                        ?: error("'$alias' holds a ${key.algorithm} ${key.javaClass.simpleName}; only private keys can be re-encoded")
                    val chain = keyStore.getCertificateChain(alias).orEmpty()
                    if (chain.isEmpty()) error("'$alias' has no certificate chain")
                    KeyEntry(alias, privateKey, chain.map(::asX509))
                }

                keyStore.isCertificateEntry(alias) ->
                    CertificateEntry(alias, asX509(keyStore.getCertificate(alias) ?: error("no certificate under '$alias'")))

                else -> error("'$alias' is neither a key nor a certificate entry")
            }
        }

    private fun asX509(certificate: Certificate): X509Certificate = certificate as? X509Certificate
        ?: error("only X.509 certificates can be re-encoded, was ${certificate.type}")

    // ------------------------------------------------------------------ writing

    private fun build(entries: List<Pkcs12Entry>, password: CharArray): ByteArray {
        val builder = PKCS12PfxPduBuilder()
        val certificateBags = mutableListOf<PKCS12SafeBag>()

        entries.forEach { entry ->
            when (entry) {
                is KeyEntry -> {
                    // Equal friendlyName and localKeyId on the key bag and on the leaf certificate is
                    // what makes a JCA provider associate the two; without it the store loads as a
                    // key with no certificate and an orphan certificate.
                    val localKeyId = DEROctetString(
                        MessageDigest.getInstance("SHA-256").digest(entry.chain.first().publicKey.encoded),
                    )
                    builder.addData(
                        JcaPKCS12SafeBagBuilder(entry.privateKey, encryptor(password)).apply {
                            addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString(entry.alias))
                            addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, localKeyId)
                        }.build(),
                    )
                    entry.chain.forEachIndexed { index, certificate ->
                        certificateBags += JcaPKCS12SafeBagBuilder(certificate).apply {
                            // Only the leaf is named. An issuer certificate carrying the alias would
                            // come back as a second entry under the same name.
                            if (index == 0) {
                                addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString(entry.alias))
                                addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, localKeyId)
                            }
                        }.build()
                    }
                }

                is CertificateEntry -> certificateBags += JcaPKCS12SafeBagBuilder(entry.certificate).apply {
                    addBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, DERBMPString(entry.alias))
                    addBagAttribute(TRUSTED_KEY_USAGE, ANY_EXTENDED_KEY_USAGE)
                }.build()
            }
        }

        if (certificateBags.isNotEmpty()) {
            builder.addEncryptedData(encryptor(password), certificateBags.toTypedArray())
        }

        return builder.build(
            JcePKCS12MacCalculatorBuilder(NISTObjectIdentifiers.id_sha256)
                .setProvider(bouncyCastle)
                .setIterationCount(ITERATIONS),
            password,
        ).encoded
    }

    private fun encryptor(password: CharArray): OutputEncryptor = JcePKCSPBEOutputEncryptorBuilder(
        NISTObjectIdentifiers.id_aes256_CBC,
    ).setProvider(bouncyCastle)
        .setIterationCount(ITERATIONS)
        .setPRF(AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA256, DERNull.INSTANCE))
        .build(password)

    // ------------------------------------------------------------------ sniffing

    private fun sniff(pfxBytes: ByteArray): Boolean {
        val pfx = Pfx.getInstance(ASN1Primitive.fromByteArray(pfxBytes))
        pfx.macData?.let { if (it.iterationCount > BigInteger.valueOf(LEGACY_ITERATION_THRESHOLD.toLong())) return true }

        val authenticatedSafe = AuthenticatedSafe.getInstance(
            ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(pfx.authSafe.content).octets),
        )
        authenticatedSafe.contentInfo.forEach { contentInfo ->
            when (contentInfo.contentType) {
                // The certificate bags: encrypted as a unit, so the parameters are right here.
                PKCSObjectIdentifiers.encryptedData ->
                    if (isExpensive(EncryptedData.getInstance(contentInfo.content).encryptionAlgorithm)) return true

                // Plain safe bags. The shrouded key bags inside carry their own PBE parameters.
                PKCSObjectIdentifiers.data -> {
                    val bags = ASN1Sequence.getInstance(ASN1OctetString.getInstance(contentInfo.content).octets)
                    for (index in 0 until bags.size()) {
                        val bag = SafeBag.getInstance(bags.getObjectAt(index))
                        if (bag.bagId != PKCSObjectIdentifiers.pkcs8ShroudedKeyBag) continue
                        if (isExpensive(EncryptedPrivateKeyInfo.getInstance(bag.bagValue).encryptionAlgorithm)) return true
                    }
                }
            }
        }
        return false
    }

    private fun isExpensive(algorithm: AlgorithmIdentifier): Boolean = when {
        // 1.2.840.113549.1.12.1.* — pbeWithSHAAnd3_KeyTripleDES_CBC, pbeWithSHAAnd40BitRC2_CBC and
        // the rest of the SHA-1 based family. BouncyCastle writes these at 600,000.
        algorithm.algorithm.on(PKCSObjectIdentifiers.pkcs_12PbeIds) -> true
        algorithm.algorithm == PKCSObjectIdentifiers.id_PBES2 -> pbkdf2Iterations(algorithm)
            ?.let { it > BigInteger.valueOf(LEGACY_ITERATION_THRESHOLD.toLong()) } == true
        // Anything else is unrecognised, and an unrecognised algorithm is not a reason to rewrite a
        // file whose only copy of an RSA identity this is.
        else -> false
    }

    private fun pbkdf2Iterations(algorithm: AlgorithmIdentifier): BigInteger? {
        val pbes2 = PBES2Parameters.getInstance(algorithm.parameters)
        if (pbes2.keyDerivationFunc.algorithm != PKCSObjectIdentifiers.id_PBKDF2) return null
        return PBKDF2Params.getInstance(pbes2.keyDerivationFunc.parameters).iterationCount
    }

    // ------------------------------------------------------------------ providers

    /** Mirrors [JvmKeyStoreClient]'s rule: demote BouncyCastle only for a SUN-flavoured keystore. */
    private inline fun <T> withProviderMatching(keyStore: KeyStore, block: () -> T): T {
        val needsDemote = keyStore.provider.name == "SUN" || keyStore.provider.name == "SunJSSE"
        return if (needsDemote) withBouncyCastleDemoted(block) else block()
    }

    private inline fun <T> withBouncyCastleDemoted(block: () -> T): T {
        val present = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) != null
        if (present) Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        try {
            return block()
        } finally {
            if (present && Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.insertProviderAt(BouncyCastleProvider(), 1)
            }
        }
    }
}

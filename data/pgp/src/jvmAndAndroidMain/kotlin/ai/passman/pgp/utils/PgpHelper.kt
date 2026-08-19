package ai.passman.pgp.utils

import ai.passman.pgp.utils.TextUtils.processLine
import ai.passman.pgp.utils.TextUtils.readInputLine
import ai.passman.logging.KLogger
import java.io.*
import java.security.SecureRandom
import java.security.Security
import java.security.SignatureException
import java.util.*
import org.bouncycastle.bcpg.*
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openpgp.*
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.*
import org.bouncycastle.util.io.Streams

object PgpHelper {
    var BOUNCY_PROVIDER = BouncyCastleProvider()

    fun encryptFile(outStream: OutputStream, plaintext: File, encKey: PGPPublicKey, armor: Boolean, withIntegrityCheck: Boolean) {
        if (encKey.isEncryptionKey.not()){
            return
        }

        val out = if (armor) { ArmoredOutputStream(outStream) } else { outStream }
        val bOut = ByteArrayOutputStream()
        val comData = PGPCompressedDataGenerator(PGPCompressedData.ZIP)

        PGPUtil.writeFileToLiteralData(
            comData.open(bOut),
            PGPLiteralData.BINARY,
            plaintext,
        )
        comData.close()


        val dataEncryptor: JcePGPDataEncryptorBuilder =
            JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                .setWithIntegrityPacket(withIntegrityCheck)
                .setSecureRandom(SecureRandom())
                .setProvider(BOUNCY_PROVIDER)
        val cPk = PGPEncryptedDataGenerator(dataEncryptor)
        val methodGenerator =
            JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider(BOUNCY_PROVIDER).setSecureRandom(SecureRandom())
        cPk.addMethod(methodGenerator)
        val bytes: ByteArray = bOut.toByteArray()
        val cOut: OutputStream = cPk.open(out, bytes.size.toLong())
        cOut.write(bytes)
        cOut.close()
        out.close()
    }

    fun decryptFile(inputStream: InputStream, out: OutputStream, secretKeyIn: PGPSecretKeyRing, passphrase: String) {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME)
        Security.insertProviderAt(BOUNCY_PROVIDER, 1)

        val decoderStream = PGPUtil.getDecoderStream(inputStream)
        var pgpObjectFactory = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())
        val encryptedDataList: PGPEncryptedDataList
        val nextObject = pgpObjectFactory.nextObject()

        encryptedDataList = if (nextObject is PGPEncryptedDataList) {
            nextObject
        } else {
            pgpObjectFactory.nextObject() as PGPEncryptedDataList
        }

        encryptedDataList.encryptedDataObjects.forEach { encryptedData ->
            val messageInputStream = when (encryptedData) {
                is PGPPBEEncryptedData -> {
                    val dataDecryptorFactoryBuilder = JcePBEDataDecryptorFactoryBuilder()
                        .setProvider(BOUNCY_PROVIDER).build(passphrase.toCharArray())
                    encryptedData.getDataStream(dataDecryptorFactoryBuilder)
                }
                is PGPPublicKeyEncryptedData -> {
                    val sKeyID = encryptedData.keyIdentifier.keyId
                    val sKey = PgpKeys.findSecretKey(secretKeyIn, sKeyID, passphrase)
                    val dataDecryptorFactoryBuilder = JcePublicKeyDataDecryptorFactoryBuilder()
                        .setProvider(BOUNCY_PROVIDER).setContentProvider(BOUNCY_PROVIDER).build(sKey)
                    encryptedData.getDataStream(dataDecryptorFactoryBuilder)
                }
                else -> throw PGPException("message unknown message type.")
            }

            pgpObjectFactory = PGPObjectFactory(messageInputStream, BcKeyFingerprintCalculator())
            var messageObject: Any = pgpObjectFactory.nextObject()
            if (messageObject is PGPCompressedData) {
                val compressedData = messageObject
                messageObject = PGPObjectFactory(compressedData.dataStream, BcKeyFingerprintCalculator()).nextObject()
            }
            when (messageObject) {
                is PGPLiteralData -> {
                    val unc = messageObject.inputStream
                    var ch: Int
                    while (unc.read().also { ch = it } >= 0) {
                        out.write(ch)
                    }
                }
                is PGPOnePassSignatureList -> {
                    throw PGPException("Encrypted message contains a signed message - not literal data.")
                }
                else -> {
                    throw PGPException("Message is not a simple encrypted file - type unknown.")
                }
            }

            if (encryptedData.isIntegrityProtected) {
                if (!encryptedData.verify()) {
                    throw PGPException("Message failed integrity check")
                }
            }
        }
    }

    fun clearSign(message: ByteArray, pgpSecKey: PGPSecretKey, pass: CharArray, digestName: String = "SHA256"): ByteArray {
        val out = ByteArrayOutputStream()
        val digest: Int = when (digestName) {
            "SHA256" -> PGPUtil.SHA256
            "SHA384" -> PGPUtil.SHA384
            "SHA512" -> PGPUtil.SHA512
            else -> PGPUtil.SHA256
        }

        val cryptFactory = JcePBESecretKeyDecryptorBuilder().setProvider(BOUNCY_PROVIDER).build(pass)
        val pgpPrivKey = pgpSecKey.extractPrivateKey(cryptFactory)

        val sGen = PGPSignatureGenerator(
            JcaPGPContentSignerBuilder(pgpSecKey.publicKey.algorithm, digest).setProvider(BOUNCY_PROVIDER),
            pgpSecKey.publicKey,
        )
        val spGen = PGPSignatureSubpacketGenerator()
        sGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, pgpPrivKey)
        val it: Iterator<*> = pgpSecKey.publicKey.userIDs
        if (it.hasNext()) {
            spGen.addSignerUserID(false, it.next() as String?)
            sGen.setHashedSubpackets(spGen.generate())
        }
        val fIn: InputStream = ByteArrayInputStream(message)
        val aOut = ArmoredOutputStream(out)
        aOut.beginClearText(digest)

        // note the last \n/\r/\r\n in the file is ignored
        val lineOut = ByteArrayOutputStream()
        var lookAhead: Int = readInputLine(lineOut, fIn)
        processLine(aOut, sGen, lineOut.toByteArray())
        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, fIn)
                sGen.update('\r'.code.toByte())
                sGen.update('\n'.code.toByte())
                processLine(aOut, sGen, lineOut.toByteArray())
            } while (lookAhead != -1)
        }
        fIn.close()
        aOut.endClearText()
        val bOut = BCPGOutputStream(aOut)
        sGen.generate().encode(bOut)
        aOut.close()
        return out.toByteArray()
    }

    fun verifyClearSign(message: ByteArray, publicKeyPath: String): Boolean = runCatching {
        KLogger.d { "verifyClearSign: input bytes=${message.size}" }
        KLogger.d { "verifyClearSign: input received" }
        KLogger.d { "verifyClearSign: publicKeyPath=$publicKeyPath" }

        val aIn = ArmoredInputStream(ByteArrayInputStream(message))
        val bout = ByteArrayOutputStream()

        // write out signed section.
        // note: trailing white space needs to be removed from the end of
        // each line RFC 4880 Section 7.1
        val lineOut = ByteArrayOutputStream()
        // ArmoredInputStream parses the BEGIN PGP SIGNED MESSAGE header in its constructor,
        // so isClearText is already true here for a properly-formatted clearsigned input.
        val isFirstLineClearText = aIn.isClearText
        KLogger.d { "verifyClearSign: isFirstLineClearText=$isFirstLineClearText" }
        var lookAhead = readInputLine(lineOut, aIn)
        KLogger.d { "verifyClearSign: first read lookAhead=$lookAhead, lineOutSize=${lineOut.size()}" }
        if (isFirstLineClearText) {
            // Always write the first line we read while in clearText mode, even when
            // lookAhead came back as -1 (single-line cleartext: the byte after the trailing
            // newline triggers the transition to signature mode and returns -1).
            bout.write(lineOut.toByteArray())
            while (lookAhead != -1 && aIn.isClearText) {
                lookAhead = readInputLine(lineOut, lookAhead, aIn)
                KLogger.d { "verifyClearSign: loop read lookAhead=$lookAhead, lineOutSize=${lineOut.size()}" }
                bout.write(lineOut.toByteArray())
            }
        }
        KLogger.d { "verifyClearSign: cleartext bytes=${bout.size()}" }

        var pgpFact = PGPObjectFactory(aIn, JcaKeyFingerprintCalculator())

        val p3: PGPSignatureList = when (val o = pgpFact.nextObject()) {
            is PGPCompressedData -> {
                pgpFact = PGPObjectFactory(o.dataStream, BcKeyFingerprintCalculator())
                pgpFact.nextObject() as? PGPSignatureList
                    ?: error("no signature packet inside compressed data")
            }
            is PGPSignatureList -> o
            null -> error("no PGP object found after cleartext; armored input may be malformed or missing the signature block")
            else -> error("unexpected PGP object type after cleartext: ${o.javaClass.simpleName}")
        }

        val sig = p3[0]
        KLogger.d { "verifyClearSign: signature keyId=${sig.keyID}, signatureType=0x${sig.signatureType.toString(16)}, hashAlgo=${sig.hashAlgorithm}, keyAlgo=${sig.keyAlgorithm}" }

        val publicKey = PgpKeys.findPublicKeyById(publicKeyPath, sig.keyID)
            ?: error("no public key matching signature keyId 0x${sig.keyID.toString(16)} found in $publicKeyPath")
        KLogger.d { "verifyClearSign: resolved publicKey keyId=${publicKey.keyID}, fingerprint=${publicKey.fingerprint.toHex()}, algo=${publicKey.algorithm}" }

        sig.init(JcaPGPContentVerifierBuilderProvider().setProvider(BOUNCY_PROVIDER), publicKey)

        // read the input, making sure we ignore the last newline.
        val sigIn = ByteArrayInputStream(bout.toByteArray())
        lookAhead = readInputLine(lineOut, sigIn)
        processLine(sig, lineOut.toByteArray())
        if (lookAhead != -1) {
            do {
                lookAhead = readInputLine(lineOut, lookAhead, sigIn)
                sig.update('\r'.code.toByte())
                sig.update('\n'.code.toByte())
                processLine(sig, lineOut.toByteArray())
            } while (lookAhead != -1)
        }
        sigIn.close()
        KLogger.d { "verifyClearSign: signature input bytes=${bout.size()}" }
        val result = sig.verify()
        KLogger.d { "verifyClearSign: sig.verify()=$result" }
        result
    }.onFailure {
        KLogger.e(it) { "verifyClearSign: failed with ${it.javaClass.simpleName}: ${it.message}" }
    }.getOrDefault(false)

    private fun ByteArray.toHex(): String = joinToString("") { ((it.toInt() and 0xff)).toString(16).padStart(2, '0') }

    fun sign(message: ByteArray, secretKey: PGPSecretKey, secretPwd: String, armor: Boolean, digestName: String = "SHA256"): ByteArray {
        val out = ByteArrayOutputStream()
        val digest: Int = when (digestName) {
            "SHA256" -> PGPUtil.SHA256
            "SHA384" -> PGPUtil.SHA384
            "SHA512" -> PGPUtil.SHA512
            else -> PGPUtil.SHA256
        }

        val theOut = if (armor) ArmoredOutputStream(out) else out
        val pgpPrivKey = secretKey.extractPrivateKey(
            JcePBESecretKeyDecryptorBuilder().setProvider(BOUNCY_PROVIDER).build(secretPwd.toCharArray())
        )
        val sGen = PGPSignatureGenerator(
            JcaPGPContentSignerBuilder(secretKey.publicKey.algorithm, digest)
                .setProvider(BOUNCY_PROVIDER),
            secretKey.publicKey,
        )
        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey)
        val it: Iterator<*> = secretKey.publicKey.userIDs
        if (it.hasNext()) {
            val spGen = PGPSignatureSubpacketGenerator()
            spGen.addSignerUserID(false, it.next() as String?)
            sGen.setHashedSubpackets(spGen.generate())
        }
        val cGen = PGPCompressedDataGenerator(PGPCompressedData.ZLIB)
        val bOut = BCPGOutputStream(cGen.open(theOut))
        sGen.generateOnePassVersion(false).encode(bOut)
        val lGen = PGPLiteralDataGenerator()
        val lOut = lGen.open(bOut, PGPLiteralData.BINARY, "filename", Date(), ByteArray(4096))
        val fIn: InputStream = ByteArrayInputStream(message)
        var ch: Int
        while (fIn.read().also { ch = it } >= 0) {
            lOut.write(ch)
            sGen.update(ch.toByte())
        }
        lGen.close()
        sGen.generate().encode(bOut)
        cGen.close()
        theOut.close()
        return out.toByteArray()
    }

    fun verifySignature(signatureData: ByteArray, publicKeyPath: String): Boolean {
        val decoderStream = PGPUtil.getDecoderStream(ByteArrayInputStream(signatureData))
        var plainFact = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())

        var message: Any?
        var onePassSignatureList: PGPOnePassSignatureList? = null
        var signatureList: PGPSignatureList? = null
        var compressedData: PGPCompressedData

        message = plainFact.nextObject()

        val actualOutput = ByteArrayOutputStream()
        while (message != null) {
            if (message is PGPCompressedData) {
                compressedData = message
                plainFact = PGPObjectFactory(compressedData.dataStream, JcaKeyFingerprintCalculator())
                message = plainFact.nextObject()
            }
            when (message) {
                is PGPLiteralData -> Streams.pipeAll(message.inputStream, actualOutput)
                is PGPOnePassSignatureList -> onePassSignatureList = message
                is PGPSignatureList -> signatureList = message
                else -> throw PGPException("message unknown message type.")
            }
            message = plainFact.nextObject()
        }
        actualOutput.close()
        val output = actualOutput.toByteArray()

        // verify signature
        if (onePassSignatureList == null || signatureList == null) {
            return false
        }

        for (i in 0 until onePassSignatureList.size()) {
            val ops = onePassSignatureList[i]
            val publicKey = PgpKeys.findPublicKeyById(publicKeyPath, ops.keyID)
            if (publicKey == null) {
                return false
            }
            ops.init(JcaPGPContentVerifierBuilderProvider().setProvider(BOUNCY_PROVIDER), publicKey)
            ops.update(output)
            val signature = signatureList[i]
            if (!ops.verify(signature)) {
                return false
            }
        }

        return true
    }

    fun signAndEncrypt(
        message: ByteArray,
        secretKey: PGPSecretKey,
        secretPwd: String,
        publicKey: PGPPublicKey,
        armored: Boolean
    ): ByteArray {
        return try {
            val out = ByteArrayOutputStream()
            val encryptedDataGenerator = PGPEncryptedDataGenerator(
                JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                    .setWithIntegrityPacket(true)
                    .setSecureRandom(SecureRandom())
                    .setProvider(BOUNCY_PROVIDER)
            )
            encryptedDataGenerator.addMethod(
                JcePublicKeyKeyEncryptionMethodGenerator(publicKey)
                    .setSecureRandom(SecureRandom())
                    .setProvider(BOUNCY_PROVIDER)
            )
            val theOut = if (armored) ArmoredOutputStream(out) else out
            val encryptedOut = encryptedDataGenerator.open(theOut, ByteArray(4096))
            val compressedDataGenerator = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
            val compressedOut = compressedDataGenerator.open(encryptedOut, ByteArray(4096))
            val privateKey = secretKey.extractPrivateKey(
                JcePBESecretKeyDecryptorBuilder().setProvider(BOUNCY_PROVIDER).build(secretPwd.toCharArray())
            )
            val signatureGenerator = PGPSignatureGenerator(
                JcaPGPContentSignerBuilder(secretKey.publicKey.algorithm, HashAlgorithmTags.SHA512)
                    .setProvider(BOUNCY_PROVIDER),
                secretKey.publicKey,
            )
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey)
            val userIds = secretKey.publicKey.userIDs
            if (userIds.hasNext()) {
                val spGen = PGPSignatureSubpacketGenerator()
                spGen.addSignerUserID(false, userIds.next())
                signatureGenerator.setHashedSubpackets(spGen.generate())
            }
            signatureGenerator.generateOnePassVersion(false).encode(compressedOut)
            val literalDataGenerator = PGPLiteralDataGenerator()
            val literalOut: OutputStream = literalDataGenerator
                .open(compressedOut, PGPLiteralData.BINARY, "filename", Date(), ByteArray(4096))

            val inputStream = ByteArrayInputStream(message)
            val buf = ByteArray(4096)
            var len: Int
            while (inputStream.read(buf).also { len = it } > 0) {
                literalOut.write(buf, 0, len)
                signatureGenerator.update(buf, 0, len)
            }
            inputStream.close()
            literalDataGenerator.close()
            signatureGenerator.generate().encode(compressedOut)
            compressedDataGenerator.close()
            encryptedDataGenerator.close()
            theOut.close()
            out.toByteArray()
        } catch (e: Exception) {
            throw PGPException("Error in signAndEncrypt", e)
        }
    }

    fun decryptAndVerify(
        encryptedMessage: ByteArray,
        secretKeyRing: PGPSecretKeyRing,
        secretPwd: String,
        publicKeyPath: String,
    ): ByteArray {
        return try {
            val factory = PGPObjectFactory(
                PGPUtil.getDecoderStream(ByteArrayInputStream(encryptedMessage)),
                JcaKeyFingerprintCalculator()
            )
            val first = factory.nextObject()
            val list = first as? PGPEncryptedDataList ?: factory.nextObject()
            val encryptedDataList = list as PGPEncryptedDataList
            var matchingEntry: Pair<PGPPublicKeyEncryptedData, PGPPrivateKey>? = null
            for (encryptedData in encryptedDataList.encryptedDataObjects) {
                if (encryptedData is PGPPublicKeyEncryptedData) {
                    val secretKey = PgpKeys.findSecretKey(secretKeyRing, encryptedData.keyIdentifier.keyId, secretPwd)
                    if (secretKey != null) {
                        matchingEntry = encryptedData to secretKey
                        break
                    }
                }
            }
            val (pbe, sKey) = matchingEntry
                ?: throw PGPException("no matching secret key found for encrypted message")
            val clear = pbe.getDataStream(JcePublicKeyDataDecryptorFactoryBuilder().setProvider(BOUNCY_PROVIDER).build(sKey))
            var plainFact = PGPObjectFactory(clear, JcaKeyFingerprintCalculator())
            var message: Any?
            var onePassSignatureList: PGPOnePassSignatureList? = null
            var signatureList: PGPSignatureList? = null
            var compressedData: PGPCompressedData
            message = plainFact.nextObject()
            val actualOutput = ByteArrayOutputStream()
            while (message != null) {
                if (message is PGPCompressedData) {
                    compressedData = message
                    plainFact = PGPObjectFactory(compressedData.dataStream, JcaKeyFingerprintCalculator())
                    message = plainFact.nextObject()
                }
                when (message) {
                    is PGPLiteralData -> Streams.pipeAll(message.inputStream, actualOutput)
                    is PGPOnePassSignatureList -> onePassSignatureList = message
                    is PGPSignatureList -> signatureList = message
                    else -> throw PGPException("message unknown message type.")
                }
                message = plainFact.nextObject()
            }
            actualOutput.close()
            val output = actualOutput.toByteArray()

            // verify signature
            if (onePassSignatureList == null || signatureList == null) {
                throw PGPException("Poor PGP. Signatures not found.")
            } else {
                for (i in 0 until onePassSignatureList.size()) {
                    val ops = onePassSignatureList[i]
                    val publicKey = PgpKeys.findPublicKeyById(publicKeyPath, ops.keyID)
                        ?: throw SignatureException("No public key found for signature key ID ${ops.keyID}")
                    ops.init(JcaPGPContentVerifierBuilderProvider().setProvider(BOUNCY_PROVIDER), publicKey)
                    ops.update(output)
                    val signature = signatureList[i]
                    if (!ops.verify(signature)) {
                        throw SignatureException("Signature verification failed")
                    }
                }
            }
            if (pbe.isIntegrityProtected && !pbe.verify()) {
                throw PGPException("Data is integrity protected but integrity is lost.")
            }
            actualOutput.toByteArray()
        } catch (e: Exception) {
            throw PGPException(e.cause?.message ?: e.message ?: "Error in decryptAndVerify", e)
        }
    }

    fun createSignature(
        fileName: String,
        secretKeyPath: String,
        out: OutputStream?,
        pass: CharArray?,
        armor: Boolean
    ): ByteArray {
        val pgpSecKey: PGPSecretKey = PgpKeys.readSecretKey(secretKeyPath)
        val pgpPrivKey: PGPPrivateKey =
            pgpSecKey.extractPrivateKey(JcePBESecretKeyDecryptorBuilder().setProvider(BOUNCY_PROVIDER).build(pass))
        val sGen = PGPSignatureGenerator(
            JcaPGPContentSignerBuilder(pgpSecKey.publicKey.algorithm, HashAlgorithmTags.SHA256).setProvider(BOUNCY_PROVIDER),
            pgpSecKey.publicKey,
        )
        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey)
        val byteOut = ByteArrayOutputStream()
        val aOut = ArmoredOutputStream(byteOut)
        val bOut = BCPGOutputStream(byteOut)
        val fIn: InputStream = BufferedInputStream(FileInputStream(fileName))
        var ch: Int
        while (fIn.read().also { ch = it } >= 0) {
            sGen.update(ch.toByte())
        }
        aOut.endClearText()
        fIn.close()
        sGen.generate().encode(bOut)
        if (armor) {
            aOut.close()
        }
        return byteOut.toByteArray()
    }

    fun extractContentFromClearSign(signedMessage: ByteArray): ByteArray {
        return try {
            val aIn = ArmoredInputStream(ByteArrayInputStream(signedMessage))
            val bout = ByteArrayOutputStream()

            //
            // write out signed section using the local line separator.
            // note: trailing white space needs to be removed from the end of
            // each line RFC 4880 Section 7.1
            //
            val lineOut = ByteArrayOutputStream()
            val isFirstLineText: Boolean = aIn.isClearText
            var lookAhead: Int = readInputLine(lineOut, aIn)
            if (lookAhead != -1 && isFirstLineText) {
                bout.write(lineOut.toByteArray())
                while (lookAhead != -1 && aIn.isClearText) {
                    lookAhead = readInputLine(lineOut, lookAhead, aIn)
                    bout.write(lineOut.toByteArray())
                }
            }
            bout.toByteArray()
        } catch (ex: Exception) {
            throw PGPException("", ex)
        }
    }

    fun createDetachedSignature(secretKey: PGPSecretKey, password: CharArray, data: ByteArray): ByteArray {
        val bOut = ByteArrayOutputStream()
        val aOut = ArmoredOutputStream(bOut)

        val sGen = PGPSignatureGenerator(
            JcaPGPContentSignerBuilder(secretKey.publicKey.algorithm, PGPUtil.SHA256).setProvider(BOUNCY_PROVIDER),
            secretKey.publicKey,
        )
        val pgpPrivKey = secretKey.extractPrivateKey(
            JcePBESecretKeyDecryptorBuilder().setProvider(BOUNCY_PROVIDER).build(password)
        )
        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey)
        for (i in data.indices) {
            sGen.update(data[i])
        }

        val bcpOut = BCPGOutputStream(aOut)
        sGen.generate().encode(bcpOut)
        aOut.close()
        return bOut.toByteArray()
    }

    fun verifyDetachedSignature(verifyingKey: PGPPublicKey, pgpSignature: ByteArray): Boolean {
        val decoderStream = PGPUtil.getDecoderStream(ByteArrayInputStream(pgpSignature))
        val pgpFact = PGPObjectFactory(decoderStream, BcKeyFingerprintCalculator())

//        val pgpFact = PGPObjectFactory(pgpSignature)
        val sigList = pgpFact.nextObject() as PGPSignatureList
        val sig = sigList[0]
        sig.init(JcaPGPContentVerifierBuilderProvider().setProvider(BOUNCY_PROVIDER), verifyingKey)
        // sig.update(data)
        return sig.verify()
    }

    fun gpgDecrypt(inputStream: InputStream, out: OutputStream, keyIn: InputStream, passwd: CharArray): InputStream? {
        val factory = PGPObjectFactory(
            PGPUtil.getDecoderStream(inputStream),
            BcKeyFingerprintCalculator()
        )
        return nextDecryptedStream(factory, out, keyIn, passwd)
    }

    private fun nextDecryptedStream(factory: PGPObjectFactory, out: OutputStream, keyIn: InputStream, passwd: CharArray): InputStream? {
        var pgpObj: Any
        while (factory.nextObject().also { pgpObj = it } != null) { // NOPMD
            when (pgpObj) {
                is PGPEncryptedDataList -> {
                    val enc = pgpObj as PGPEncryptedDataList
                    val encryptedDataObjects: Iterator<*> = enc.encryptedDataObjects
                    if (!encryptedDataObjects.hasNext()) {
                        throw PGPException("Decryption failed - No encrypted data found!")
                    }

                    val privateKey: PGPPrivateKey? = null
                    var sKey: PGPPrivateKey? = null
                    var pbe: PGPPublicKeyEncryptedData? = null
                    while (sKey == null && encryptedDataObjects.hasNext()) {
                        pbe = encryptedDataObjects.next() as PGPPublicKeyEncryptedData
                        sKey = PgpKeys.findSecretKey(keyIn, pbe.keyIdentifier.keyId, passwd)
                    }

                    requireNotNull(sKey) { "Secret key for message not found." }

                    // decrypt the data
                    val plainText: InputStream = pbe!! // NOPMD: CloseResource
                        .getDataStream(BcPublicKeyDataDecryptorFactory(privateKey)) // NOPMD: AvoidInstantiatingObjectsInLoops
                    val nextFactory = PGPObjectFactory(
                        plainText,
                        BcKeyFingerprintCalculator()
                    ) // NOPMD: AvoidInstantiatingObjectsInLoops
                    return nextDecryptedStream(nextFactory, out, keyIn, passwd)
                }
                is PGPCompressedData -> {
                    val nextFactory = PGPObjectFactory(
                        (pgpObj as PGPCompressedData).dataStream, BcKeyFingerprintCalculator()
                    )
                    return nextDecryptedStream(nextFactory, out, keyIn, passwd) // NOPMD: OnlyOneReturn
                }
                is PGPOnePassSignatureList -> {
                    //                if (signatureValidationStrategy.isRequireSignatureCheck()) {
                    //                    state.setSignatureFactory(factory)
                    //
                    //                    // verify the signature
                    //                    val onePassSignatures = pgpObj as PGPOnePassSignatureList
                    //                    for (signature: PGPOnePassSignature in onePassSignatures) {
                    //                        val pubKey: PGPPublicKey = config.getPublicKeyRings()
                    //                            .getPublicKey(signature.getKeyID())
                    //                        val isHavePublicKeyForSignatureInKeyring = pubKey != null
                    //                        if (isHavePublicKeyForSignatureInKeyring) {
                    //                            signature.init(pgpContentVerifierBuilderProvider, pubKey)
                    //                            state.addSignature(signature)
                    //                        } else {
                    // //                            LOGGER.info(
                    // //                                "Found signature but public key '0x{}' was not found in the keyring.",
                    // //                                java.lang.Long.toHexString(signature.getKeyID())
                    // //                            )
                    //                        }
                    //                    }
                    //                    if (!state.hasVerifiableSignatures()) {
                    //                        throw PGPException(
                    //                            (
                    //                                "Signature checking is required but none of the public keys used to sign the data "
                    //                                    + "were found in the keyring'!")
                    //                        )
                    //                    }
                    //                } else {
                    //                    // LOGGER.trace("Signature check disabled - ignoring contained signature")
                    //                }
                }
                is PGPLiteralData -> {
                    // LOGGER.trace("Found instance of PGPLiteralData")
                    val literalDataInputStream = (pgpObj as PGPLiteralData).inputStream
//                        return if (signatureValidationStrategy.isRequireSignatureCheck()) {
//                            if (!state.hasVerifiableSignatures()) {
//                                throw PGPException("Signature checking is required but message was not signed!")
//                            }
//                            MDCValidatingInputStream(
//                                SignatureValidatingInputStream(
//                                    literalDataInputStream,
//                                    state, signatureValidationStrategy
//                                ), pbe
//                            ) // NOPMD: OnlyOneReturn
//                        } else {
//                            MDCValidatingInputStream(literalDataInputStream, pbe) // NOPMD: OnlyOneReturn
//                        }
                }
                else -> { // keep on searching...
                    //                if (LOGGER.isTraceEnabled()) {
                    //                    LOGGER.trace("Skipping pgp Object of Type {}", pgpObj.javaClass.simpleName)
                    //                }
                }
            }
        }
        throw PGPException("No data found")
    }
}

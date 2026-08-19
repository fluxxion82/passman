package ai.passman.crypto.vault

import ai.passman.crypto.CryptoEnvelope
import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.crypto.EnvelopeCodec
import ai.passman.crypto.JvmCryptoService
import ai.passman.crypto.keyring.KeyringEnvelope
import ai.passman.crypto.keyring.KeyringSubkeys
import java.security.GeneralSecurityException
import java.security.KeyPairGenerator
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Rules this file keeps, carried over from [ai.passman.crypto.keyring.KeyringEnvelopeTest]:
 *
 * 1. **No `assertFails`.** It wraps `runCatching`, which catches `Throwable`, so an unrelated
 *    `IllegalStateException` — or an `OutOfMemoryError` — would read as a pass. Every rejection names
 *    the exact subclass it must get, because the whole point of [VaultFailure] is that the three cases
 *    are told apart at the call site.
 * 2. **Layout assertions use literal numbers**, never the constants the writer used. Reading the
 *    header back through `PasswordVaultCipher.PAYLOAD_NONCE_OFFSET` would make swapping two fields
 *    invisible while the on-disk format silently changed underneath every vault already written.
 * 3. **A golden vector locks the format.** [unwrapsTheGoldenVector] decrypts bytes produced by an
 *    independent encoder (JDK `Mac`-based RFC 5869 HKDF + `javax.crypto` AES-GCM, sharing no code with
 *    [KeyringSubkeys] or `PasswordVaultCipher`) written straight from the plan's spec. It is the only
 *    assertion here that still fails when the reader and the writer are changed together.
 * 4. **Where a machine-readable discriminator exists, assert on it, not on the message.** Two very
 *    different states are [VaultFailure.Malformed] — "this device has no legacy key" and "these bytes
 *    are not a vault" — and they need opposite recoveries. A test that separates them with
 *    `message.contains(...)` passes silently the first time someone rewords the string, so the
 *    separation is asserted through [VaultFailure.Malformed.legacyKeyUnavailable]. Message assertions
 *    remain only where the message carries the whole of the information (which field, which suite).
 */
class PasswordVaultCipherTest {

    private val random = SecureRandom()
    private val cryptoService = RecordingCryptoService()
    private val cipher = PasswordVaultCipher(cryptoService)

    private val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
    private val rsaPublic = CryptoKey(rsa.public)
    private val rsaPrivate = CryptoKey(rsa.private)

    private fun sessionKey(material: ByteArray = ByteArray(32).also { random.nextBytes(it) }) =
        VaultSessionKey(material)

    // --- Round trip -----------------------------------------------------------------------------

    @Test
    fun roundTripsWithTheSessionKeyAlone() {
        val key = sessionKey()
        val plain = "the vault contents — αβγ 🔐".encodeToByteArray()
        val opened = cipher.decryptVault(cipher.encryptVault(plain, key), key, failIfCalled())
        assertContentEquals(plain, opened.plaintext)
        assertFalse(opened.needsMigration, "a suite-5 vault is already current")
        assertEquals(0, cryptoService.decryptCalls, "no RSA operation on the v5 path")
    }

    @Test
    fun roundTripsAnEmptyVault() {
        val key = sessionKey()
        val opened = cipher.decryptVault(cipher.encryptVault(ByteArray(0), key), key, failIfCalled())
        assertContentEquals(ByteArray(0), opened.plaintext)
    }

    @Test
    fun twoEncryptionsOfTheSamePlaintextDiffer() {
        val key = sessionKey()
        val plain = "same input".encodeToByteArray()
        val a = cipher.encryptVault(plain, key)
        val b = cipher.encryptVault(plain, key)
        assertFalse(a.contentEquals(b), "a fresh vault root and fresh nonces must make the bytes differ")
        assertFalse(
            a.copyOfRange(6, 18).contentEquals(b.copyOfRange(6, 18)),
            "the root-wrap nonce must be fresh per write",
        )
        assertFalse(
            a.copyOfRange(66, 78).contentEquals(b.copyOfRange(66, 78)),
            "the payload nonce must be fresh per write",
        )
        assertFalse(
            a.copyOfRange(6, 18).contentEquals(a.copyOfRange(66, 78)),
            "the two nonces in one envelope must differ from each other",
        )
        assertContentEquals(plain, cipher.decryptVault(a, key, failIfCalled()).plaintext)
        assertContentEquals(plain, cipher.decryptVault(b, key, failIfCalled()).plaintext)
    }

    @Test
    fun aDifferentSessionKeyCannotOpenTheVault() {
        val envelope = cipher.encryptVault("secret".encodeToByteArray(), sessionKey())
        // Not WrongPassword: the session key was already authenticated by the keyring unwrap, so a
        // failure here is never something the user can fix by retyping.
        assertFailsWith<VaultFailure.Tampered> {
            cipher.decryptVault(envelope, sessionKey(), failIfCalled())
        }
    }

    // --- Layout ---------------------------------------------------------------------------------

    @Test
    fun envelopeMatchesTheSpecifiedLayout() {
        // Every number below is a literal from the plan's "Crypto formats" section:
        //   magic "PMNV"(4) | version(1)=1 | suite(1)=5 |
        //   rootWrapNonce(12) | wrappedRootKey(32 + 16 tag) | payloadNonce(12) | ciphertext+tag
        val plain = ByteArray(11)
        val bytes = cipher.encryptVault(plain, sessionKey())
        assertContentEquals("PMNV".encodeToByteArray(), bytes.copyOfRange(0, 4), "magic")
        assertEquals(1, bytes[4].toInt(), "version")
        assertEquals(5, bytes[5].toInt(), "suite")
        // 6 (magic+version+suite) + 12 (rootWrapNonce) + 48 (wrappedRootKey) + 12 (payloadNonce).
        assertEquals(78 + plain.size + 16, bytes.size, "header | ciphertext | 16-byte tag")
    }

    @Test
    fun offsetConstantsMatchTheSpecifiedLayout() {
        // The constants are how the rest of the codebase — and any future iOS port — reads the format,
        // so they are pinned to their spec values independently of any round trip.
        assertEquals(4, PasswordVaultCipher.VERSION_OFFSET)
        assertEquals(5, PasswordVaultCipher.SUITE_OFFSET)
        assertEquals(6, PasswordVaultCipher.ROOT_WRAP_NONCE_OFFSET)
        assertEquals(18, PasswordVaultCipher.WRAPPED_ROOT_KEY_OFFSET)
        assertEquals(66, PasswordVaultCipher.PAYLOAD_NONCE_OFFSET)
        assertEquals(78, PasswordVaultCipher.HEADER_BYTES)
        assertEquals(78, PasswordVaultCipher.PAYLOAD_OFFSET)
        assertEquals(18, PasswordVaultCipher.ROOT_WRAP_AAD_BYTES)
        assertEquals(12, PasswordVaultCipher.GCM_NONCE_BYTES)
        assertEquals(32, PasswordVaultCipher.VAULT_ROOT_BYTES)
        assertEquals(94, PasswordVaultCipher.MIN_ENVELOPE_BYTES, "header + an empty payload's tag")
    }

    @Test
    fun writesOnlySuiteFive() {
        // Suites 2 (RSA-OAEP+GCM), 3 (hybrid) and 4 (signed hybrid) are already taken by EnvelopeCodec.
        // Writing any of them here would hand a vault to a decoder that expects a wrapped key it does
        // not have. Empty and large payloads both, since the suite byte is fixed either way.
        for (size in intArrayOf(0, 1, 4096)) {
            val suite = cipher.encryptVault(ByteArray(size), sessionKey())[5]
            assertEquals(5, suite.toInt(), "suite byte for a $size-byte payload")
        }
    }

    @Test
    fun envelopeCodecRejectsASuiteFiveEnvelopeRatherThanMisreadingIt() {
        // The vault envelope shares "PMNV" with the v2/v3/v4 family, so the existing dispatch must
        // refuse suite 5 outright rather than parse its root-wrap nonce as an RSA wrapped-key length.
        val envelope = cipher.encryptVault("x".encodeToByteArray(), sessionKey())
        val error = assertFailsWith<IllegalArgumentException> {
            EnvelopeCodec.decrypt(envelope, rsa.private, hybridPrivate = null)
        }
        assertTrue(error.message!!.contains("suite"), "message was: ${error.message}")
    }

    // --- Golden vector --------------------------------------------------------------------------

    @Test
    fun unwrapsTheGoldenVector() {
        val opened = cipher.decryptVault(hex(GOLDEN_FILE), VaultSessionKey(hex(GOLDEN_DMK)), failIfCalled())
        assertEquals(GOLDEN_PLAINTEXT, opened.plaintext.decodeToString())
        assertFalse(opened.needsMigration)
    }

    @Test
    fun goldenVectorCarriesTheSpecifiedHeaderBytes() {
        val bytes = hex(GOLDEN_FILE)
        assertEquals(78 + GOLDEN_PLAINTEXT.length + 16, bytes.size)
        assertContentEquals("PMNV".encodeToByteArray(), bytes.copyOfRange(0, 4))
        assertEquals(1, bytes[4].toInt(), "version")
        assertEquals(5, bytes[5].toInt(), "suite")
        assertContentEquals(ByteArray(12) { (0xB0 + it).toByte() }, bytes.copyOfRange(6, 18), "rootWrapNonce")
        assertEquals(48, bytes.copyOfRange(18, 66).size, "wrappedRootKey = 32 + 16 tag")
        assertContentEquals(ByteArray(12) { (0xC0 + it).toByte() }, bytes.copyOfRange(66, 78), "payloadNonce")
    }

    @Test
    fun goldenVectorRootKeyIsWrappedUnderTheVaultSubkey() {
        // Independently unwraps the golden root with the HKDF subkey and the 18-byte prefix as AAD,
        // then opens the payload with that root and the full 78-byte header. If PasswordVaultCipher
        // ever switched to a different subkey label or a different AAD extent, unwrapsTheGoldenVector
        // would fail but nothing would say why; this does.
        val bytes = hex(GOLDEN_FILE)
        val wrapKey = KeyringSubkeys.vaultWrapKey(hex(GOLDEN_DMK))
        val root = gcmDecrypt(
            key = wrapKey,
            nonce = bytes.copyOfRange(6, 18),
            ciphertext = bytes.copyOfRange(18, 66),
            aad = bytes.copyOfRange(0, 18),
        )
        assertContentEquals(hex(GOLDEN_ROOT), root)
        val plain = gcmDecrypt(
            key = root,
            nonce = bytes.copyOfRange(66, 78),
            ciphertext = bytes.copyOfRange(78, bytes.size),
            aad = bytes.copyOfRange(0, 78),
        )
        assertEquals(GOLDEN_PLAINTEXT, plain.decodeToString())
    }

    // --- Authentication -------------------------------------------------------------------------

    @Test
    fun everyAuthenticatedHeaderByteIsBoundToATag() {
        val key = sessionKey()
        val envelope = cipher.encryptVault("secret".encodeToByteArray(), key)
        // 6..77 is the root-wrap nonce, the wrapped root key and the payload nonce. Bytes 0..5 change
        // what the envelope *is* rather than what it says, and are covered separately below.
        for (i in 6 until 78) {
            val tampered = envelope.copyOf().also { it[i] = (it[i] + 1).toByte() }
            assertFailsWith<VaultFailure.Tampered>("header byte $i must be authenticated") {
                cipher.decryptVault(tampered, key, failIfCalled())
            }
        }
    }

    @Test
    fun tamperedCiphertextAndTagFail() {
        val key = sessionKey()
        val envelope = cipher.encryptVault("secret".encodeToByteArray(), key)
        for (i in 78 until envelope.size) {
            val tampered = envelope.copyOf().also { it[i] = (it[i] + 1).toByte() }
            assertFailsWith<VaultFailure.Tampered>("payload byte $i must be authenticated") {
                cipher.decryptVault(tampered, key, failIfCalled())
            }
        }
    }

    @Test
    fun rootWrapAndPayloadEachBindEveryHeaderByteThatPrecedesThem() {
        // The root wrap cannot bind the whole header — the wrapped root key *is* part of the header,
        // so binding it would be circular. Each cipher binds the entire contiguous prefix in front of
        // its own ciphertext: 18 bytes for the root wrap, all 78 for the payload. Verified here with a
        // raw JCE cipher so a change to either extent fails even if writer and reader change together.
        val dmk = ByteArray(32).also { random.nextBytes(it) }
        val envelope = cipher.encryptVault("secret".encodeToByteArray(), VaultSessionKey(dmk.copyOf()))
        val wrapKey = KeyringSubkeys.vaultWrapKey(dmk)
        val rootNonce = envelope.copyOfRange(6, 18)
        val wrappedRoot = envelope.copyOfRange(18, 66)

        val root = gcmDecrypt(wrapKey, rootNonce, wrappedRoot, aad = envelope.copyOfRange(0, 18))
        assertEquals(32, root.size)
        assertFailsWith<GeneralSecurityException>("the root wrap must bind the version/suite prefix") {
            gcmDecrypt(wrapKey, rootNonce, wrappedRoot, aad = null)
        }
        assertFailsWith<GeneralSecurityException>("the root wrap must bind all 18 preceding bytes") {
            gcmDecrypt(wrapKey, rootNonce, wrappedRoot, aad = envelope.copyOfRange(0, 17))
        }

        val payloadNonce = envelope.copyOfRange(66, 78)
        val payload = envelope.copyOfRange(78, envelope.size)
        assertContentEquals(
            "secret".encodeToByteArray(),
            gcmDecrypt(root, payloadNonce, payload, aad = envelope.copyOfRange(0, 78)),
        )
        assertFailsWith<GeneralSecurityException>("the payload must bind the whole 78-byte header") {
            gcmDecrypt(root, payloadNonce, payload, aad = envelope.copyOfRange(0, 77))
        }
        assertFailsWith<GeneralSecurityException>("the payload must bind the wrapped root key too") {
            gcmDecrypt(root, payloadNonce, payload, aad = envelope.copyOfRange(0, 18))
        }
    }

    @Test
    fun everyWriteDrawsAFreshVaultRoot() {
        // The root is random per vault, not derived, so two writes under one session key must not
        // share it — reusing a root across writes would also reuse it across nonces chosen elsewhere.
        val dmk = ByteArray(32).also { random.nextBytes(it) }
        val wrapKey = KeyringSubkeys.vaultWrapKey(dmk)
        val roots = (0 until 3).map {
            val envelope = cipher.encryptVault(ByteArray(4), VaultSessionKey(dmk.copyOf()))
            gcmDecrypt(
                key = wrapKey,
                nonce = envelope.copyOfRange(6, 18),
                ciphertext = envelope.copyOfRange(18, 66),
                aad = envelope.copyOfRange(0, 18),
            ).toList()
        }
        assertEquals(3, roots.toSet().size, "each write must draw a fresh vault root")
    }

    @Test
    fun rejectsAModifiedVersion() {
        val key = sessionKey()
        val envelope = cipher.encryptVault("secret".encodeToByteArray(), key)
        envelope[4] = 2
        val error = assertFailsWith<VaultFailure.Malformed> {
            cipher.decryptVault(envelope, key, failIfCalled())
        }
        assertTrue(error.message!!.contains("version"), "message was: ${error.message}")
    }

    @Test
    fun aModifiedMagicIsNoLongerAVaultEnvelope() {
        // Editing the magic takes the bytes out of the PMNV family entirely, so they fall to the
        // legacy reader. With no legacy key available that is a Malformed artifact, not a tag failure.
        val key = sessionKey()
        for (i in 0 until 4) {
            val envelope = cipher.encryptVault("secret".encodeToByteArray(), key)
            envelope[i] = (envelope[i] + 1).toByte()
            val error = assertFailsWith<VaultFailure.Malformed>("byte $i") {
                cipher.decryptVault(envelope, key, legacyPrivateKey = { null })
            }
            assertTrue(error.legacyKeyUnavailable, "byte $i: the missing legacy key is what stopped it")
        }
    }

    @Test
    fun aForwardVaultSuiteIsReportedAsAnUnsupportedSuiteAndNeverAsAMissingLegacyKey() {
        // An older build meeting a vault a newer build wrote. The magic and version still match, so
        // "this is not a vault" is wrong, and falling through to the RSA reader would report a missing
        // .pfx — sending the user to restore an identity store that has nothing to do with the
        // problem. Suites 3 and 4 are EnvelopeCodec's wire formats: also not vault files, also not
        // something a missing legacy key would fix. failIfCalled() is the assertion that no PKCS#12
        // store is opened on the way to finding that out.
        val key = sessionKey()
        for (suite in intArrayOf(3, 4, 6, 7, 255)) {
            val envelope = cipher.encryptVault("secret".encodeToByteArray(), key)
            envelope[5] = suite.toByte()
            val error = assertFailsWith<VaultFailure.Malformed>("suite $suite") {
                cipher.decryptVault(envelope, key, failIfCalled())
            }
            assertTrue(
                error.message!!.contains("unsupported vault suite"),
                "suite $suite message was: ${error.message}",
            )
            assertFalse(error.legacyKeyUnavailable, "suite $suite is not a missing-.pfx problem")
        }
    }

    @Test
    fun rejectsATruncatedEnvelopeWithoutAnIndexException() {
        val key = sessionKey()
        val envelope = cipher.encryptVault(ByteArray(0), key)
        assertEquals(94, envelope.size, "an empty vault is exactly header + tag")
        for (length in 0 until envelope.size) {
            assertFailsWith<VaultFailure.Malformed>("truncation to $length bytes") {
                cipher.decryptVault(envelope.copyOfRange(0, length), key, legacyPrivateKey = { null })
            }
        }
    }

    // --- Legacy read path -----------------------------------------------------------------------

    @Test
    fun legacyV2EnvelopeStillDecryptsAndAsksForMigration() {
        val plain = "an RSA-wrapped vault written before the keyring".encodeToByteArray()
        val legacy = CryptoEnvelope.encrypt(plain, rsa.public)
        assertEquals(2, legacy[5].toInt(), "fixture must really be suite 2")

        var calls = 0
        val opened = cipher.decryptVault(legacy, sessionKey(), legacyPrivateKey = { calls++; rsaPrivate })
        assertContentEquals(plain, opened.plaintext)
        assertTrue(opened.needsMigration, "a v2 vault must be rewritten as v5")
        assertEquals(1, calls, "the legacy key is resolved once, not per byte and not twice")
        assertEquals(1, cryptoService.decryptCalls, "legacy reads go through CryptoService")
    }

    @Test
    fun legacyV1JsonBlobStillDecryptsAndAsksForMigration() {
        val plain = "an even older vault".encodeToByteArray()
        val legacy = CryptoEnvelope.encryptLegacyV1ForTest(plain, rsa.public)
        assertFalse(legacy[0] == 0x50.toByte() && legacy[1] == 0x4D.toByte(), "v1 is JSON, not PMNV")

        val opened = cipher.decryptVault(legacy, sessionKey(), legacyPrivateKey = { rsaPrivate })
        assertContentEquals(plain, opened.plaintext)
        assertTrue(opened.needsMigration)
    }

    @Test
    fun theLegacyKeyProviderIsNeverInvokedOnTheV5Path() {
        // The provider is lazy precisely so that a migrated vault never opens the PKCS#12 store: that
        // store is unlocked with a DMK-derived password and touching it on every read would put an
        // avoidable RSA key in memory for the whole session. A non-null parameter would force it.
        var calls = 0
        val key = sessionKey()
        val envelope = cipher.encryptVault("secret".encodeToByteArray(), key)
        repeat(3) { cipher.decryptVault(envelope, key, legacyPrivateKey = { calls++; rsaPrivate }) }
        assertEquals(0, calls, "a v5 vault must never resolve the legacy RSA key")
    }

    @Test
    fun aLegacyEnvelopeWithNoLegacyKeyIsReportedAsMalformed() {
        val legacy = CryptoEnvelope.encrypt("secret".encodeToByteArray(), rsa.public)
        val error = assertFailsWith<VaultFailure.Malformed> {
            cipher.decryptVault(legacy, sessionKey(), legacyPrivateKey = { null })
        }
        // The flag, not the prose. "The .pfx is missing" and "the vault is shredded" are both
        // Malformed and need opposite recoveries — restore the identity store versus restore the
        // vault — so the caller has to be able to tell them apart without matching on a message that
        // will eventually be reworded.
        assertTrue(error.legacyKeyUnavailable, "message was: ${error.message}")
    }

    @Test
    fun aCorruptLegacyEnvelopeIsReportedAsTampered() {
        // The state Task 5 hits when a migration read finds a damaged v2 vault: the header parses, the
        // RSA unwrap yields a DEK, the GCM tag does not verify. Untranslated this escapes as
        // javax.crypto.AEADBadTagException — the exact type commonMain cannot name, in the riskiest
        // read in the plan.
        val legacy = CryptoEnvelope.encrypt("secret".encodeToByteArray(), rsa.public)
        for (i in intArrayOf(8, legacy.size / 2, legacy.size - 1)) {
            val corrupt = legacy.copyOf().also { it[i] = (it[i] + 1).toByte() }
            assertFailsWith<VaultFailure.Tampered>("legacy byte $i") {
                cipher.decryptVault(corrupt, sessionKey(), legacyPrivateKey = { rsaPrivate })
            }
        }
    }

    @Test
    fun theWrongLegacyKeyIsReportedAsTampered() {
        // A restore that pairs this vault with another account's identity store. Untranslated this is
        // javax.crypto.BadPaddingException out of the RSA unwrap. Tampered rather than Malformed: the
        // bytes are a perfectly well-formed envelope, and — as VaultFailure.Tampered now says — it is
        // the key that is wrong here, not the vault.
        val legacy = CryptoEnvelope.encrypt("secret".encodeToByteArray(), rsa.public)
        val other = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        assertFailsWith<VaultFailure.Tampered> {
            cipher.decryptVault(legacy, sessionKey(), legacyPrivateKey = { CryptoKey(other.private) })
        }
    }

    @Test
    fun garbageBytesWithALegacyKeyAvailableAreReportedAsMalformed() {
        // No magic, so it reaches the legacy reader, which tries to parse it as v1 JSON and throws
        // kotlinx.serialization's JsonDecodingException. Untranslated that is an uncaught crash in
        // commonMain, and it is *not* a missing-key problem, so the flag must stay false.
        val garbage = ByteArray(64) { (it * 7 + 3).toByte() }
        val error = assertFailsWith<VaultFailure.Malformed> {
            cipher.decryptVault(garbage, sessionKey(), legacyPrivateKey = { rsaPrivate })
        }
        assertFalse(error.legacyKeyUnavailable, "the legacy key was available; the bytes were not a vault")
    }

    @Test
    fun aMalformedLegacyReadNeverCarriesTheFileBytes() {
        // JsonDecodingException's message embeds the input it failed to parse — here, the contents of
        // the vault file. Forwarding that message, or attaching the exception as `cause` where every
        // stack trace and every logger handed the throwable prints it, would put vault ciphertext in a
        // crash report. Neither the message nor the trace may contain a byte of the file.
        val marker = "MARKER-THAT-MUST-NOT-ESCAPE"
        val garbage = "{$marker".encodeToByteArray()
        val error = assertFailsWith<VaultFailure.Malformed> {
            cipher.decryptVault(garbage, sessionKey(), legacyPrivateKey = { rsaPrivate })
        }
        assertFalse(error.message!!.contains(marker), "message was: ${error.message}")
        assertNull(error.cause, "no cause: its message is the file's own bytes")
        assertFalse(
            error.stackTraceToString().contains(marker),
            "nothing a crash report prints may contain the file",
        )
    }

    @Test
    fun encryptVaultNeverConsultsTheLegacyKeyMaterial() {
        cipher.encryptVault("secret".encodeToByteArray(), sessionKey())
        assertEquals(0, cryptoService.encryptCalls, "writes must never wrap a key under RSA again")
    }

    // --- Session lifecycle ----------------------------------------------------------------------

    @Test
    fun createSessionProducesAKeyringThatUnlocksTheSameVault() {
        val created = cipher.createSession(PASSWORD)
        assertEquals(KeyringEnvelope.FILE_BYTES, created.keyringBytes.size)

        val plain = "written on the day the account was made".encodeToByteArray()
        val envelope = cipher.encryptVault(plain, created.sessionKey)

        val reopened = cipher.unlockSession(created.keyringBytes, PASSWORD)
        assertContentEquals(plain, cipher.decryptVault(envelope, reopened, failIfCalled()).plaintext)
    }

    @Test
    fun unlockSessionRejectsTheWrongPassword() {
        val created = cipher.createSession(PASSWORD)
        assertFailsWith<VaultFailure.WrongPassword> {
            cipher.unlockSession(created.keyringBytes, NEW_PASSWORD)
        }
    }

    @Test
    fun unlockSessionRejectsAMalformedKeyring() {
        assertFailsWith<VaultFailure.Malformed> { cipher.unlockSession(ByteArray(10), PASSWORD) }
    }

    @Test
    fun rewrapSessionChangesOnlyTheKeyring() {
        val created = cipher.createSession(PASSWORD)
        val plain = "entries that must survive a password change".encodeToByteArray()
        val envelope = cipher.encryptVault(plain, created.sessionKey)

        val rewrapped = cipher.rewrapSession(created.sessionKey, NEW_PASSWORD)
        assertFalse(rewrapped.contentEquals(created.keyringBytes), "the keyring bytes must change")

        val reopened = cipher.unlockSession(rewrapped, NEW_PASSWORD)
        // The vault bytes were never touched, and the same DMK still opens them.
        assertContentEquals(plain, cipher.decryptVault(envelope, reopened, failIfCalled()).plaintext)
        assertFailsWith<VaultFailure.WrongPassword> { cipher.unlockSession(rewrapped, PASSWORD) }
    }

    // --- VaultSessionKey ------------------------------------------------------------------------

    @Test
    fun sessionKeyToStringIsRedacted() {
        val material = ByteArray(32) { (it + 1).toByte() }
        val rendered = VaultSessionKey(material).toString()
        assertEquals("VaultSessionKey(**redacted**)", rendered)
        // Belt and braces: no rendering of the bytes in any obvious encoding leaks into a log line.
        assertFalse(rendered.contains("01020304"), "hex must not leak")
        assertFalse(rendered.contains("["), "array rendering must not leak")
        assertFalse(rendered.contains("@"), "identity hash is noise, not identity")
    }

    @Test
    fun destroyZeroesTheMaterialAndBlocksFurtherUse() {
        val material = ByteArray(32) { (it + 1).toByte() }
        val key = VaultSessionKey(material)
        key.destroy()
        assertContentEquals(ByteArray(32), material, "the caller's array is wiped in place")
        // Using a destroyed key must be loud. Silently encrypting under 32 zero bytes would produce a
        // vault that looks fine and is readable by anyone.
        assertFailsWith<IllegalStateException> { cipher.encryptVault(ByteArray(1), key) }
    }

    @Test
    fun destroyIsIdempotent() {
        val key = sessionKey()
        key.destroy()
        key.destroy()
    }

    @Test
    fun sessionKeyRejectsWrongLengthMaterial() {
        assertFailsWith<IllegalArgumentException> { VaultSessionKey(ByteArray(31)) }
        assertFailsWith<IllegalArgumentException> { VaultSessionKey(ByteArray(0)) }
    }

    // --- Helpers --------------------------------------------------------------------------------

    /** A provider that fails the test if the v5 path ever reaches for the PKCS#12-backed RSA key. */
    private fun failIfCalled(): () -> CryptoKey? = { throw AssertionError("legacy key must not be resolved") }

    private class RecordingCryptoService(private val delegate: CryptoService = JvmCryptoService()) :
        CryptoService {
        var encryptCalls = 0
            private set
        var decryptCalls = 0
            private set

        override fun encryptBytes(plain: ByteArray, publicKey: CryptoKey): ByteArray {
            encryptCalls++
            return delegate.encryptBytes(plain, publicKey)
        }

        override fun decryptBytes(cipher: ByteArray, privateKey: CryptoKey): ByteArray {
            decryptCalls++
            return delegate.decryptBytes(cipher, privateKey)
        }
    }

    private fun gcmDecrypt(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray?) =
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            aad?.let { updateAAD(it) }
        }.doFinal(ciphertext)

    private fun hex(s: String) = ByteArray(s.length / 2) {
        ((Character.digit(s[it * 2], 16) shl 4) or Character.digit(s[it * 2 + 1], 16)).toByte()
    }

    private companion object {
        const val PASSWORD = "correct horse battery staple"
        const val NEW_PASSWORD = "a completely different horse"

        /**
         * Produced once by an independent encoder written from the plan's spec (RFC 5869 HKDF-SHA256
         * over `javax.crypto.Mac`, then two `javax.crypto` AES-GCM operations), sharing no code with
         * the implementation. Inputs: DMK `(13i + 5) mod 256`, vault root `(0xF0 - i)`, root-wrap
         * nonce `b0..bb`, payload nonce `c0..cb`. Regenerating this instead of fixing the code would
         * defeat its purpose — every vault already on disk is unreadable if these bytes stop parsing.
         */
        const val GOLDEN_DMK = "05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98"
        const val GOLDEN_ROOT = "f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1"
        const val GOLDEN_PLAINTEXT = "passman vault golden vector v5"
        const val GOLDEN_FILE =
            "504d4e560105" +
                "b0b1b2b3b4b5b6b7b8b9babb" +
                "dcfdd1b381ca41ac9805c66783c39a2ef4eb72c8cc8eb553bcff5304273ef7f5" +
                "918dadbf1eff405506fe703712fcac8b" +
                "c0c1c2c3c4c5c6c7c8c9cacb" +
                "130ea1e3c9527b4c0d19238e496e8e972e457fbdd7e2e515c7d38ed3357b" +
                "66db9f910641fff854027768bffbbd15"
    }
}

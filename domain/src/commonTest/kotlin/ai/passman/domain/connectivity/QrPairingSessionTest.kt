package ai.passman.domain.connectivity

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.settings.exception.TransferFailure
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@OptIn(ExperimentalEncodingApi::class, ExperimentalCoroutinesApi::class)
class QrPairingSessionTest {
    private val ownBundle = bundle(0x11)
    private val scannerBundle = bundle(0x22)
    private val otherBundle = bundle(0x33)
    private val fingerprintService = FakeFingerprintService(Outcome.Success(ownBundle))
    private val pendingPairingState = PendingPairingState()
    private val session = QrPairingSession(
        fingerprintService = fingerprintService,
        pendingPairingState = pendingPairingState,
    )

    @Test
    fun `a valid proof arms a QR-verified pending pairing and announces it`() = runTest {
        val events = collectEvents()
        session.register(NONCE, OWNER)

        val armed = session.onInboundBundle(encoded(scannerBundle), proofFor(scannerBundle, NONCE), REMOTE_HOST)

        assertTrue(armed, "a push that verified and armed a pairing must say so")
        val event = assertIs<QrPairingEvent.VerifiedInbound>(events.single())
        assertEquals(ownBundle.safetyNumber(scannerBundle, fingerprintService), event.safetyNumber)
        assertEquals(REMOTE_HOST, event.peerAddress)
        val pending = assertNotNull(pendingPairingState.active(OWNER))
        assertTrue(pending.verifiedViaQr)
        assertEquals(REMOTE_HOST, pending.peerAddress)
        assertEquals(event.safetyNumber, pending.safetyNumber)
        assertContentEquals(encoded(scannerBundle), pending.peerBundleBytes)
    }

    @Test
    fun `a bundle swapped after the proof was made fails and leaves the nonce armed for a retry`() = runTest {
        val events = collectEvents()
        session.register(NONCE, OWNER)

        assertFalse(session.onInboundBundle(encoded(otherBundle), proofFor(scannerBundle, NONCE), REMOTE_HOST))

        val failure = assertIs<QrPairingEvent.ProofFailed>(events.single())
        assertEquals(ownBundle.safetyNumber(otherBundle, fingerprintService), failure.safetyNumber)
        assertEquals(REMOTE_HOST, failure.peerAddress)
        assertNull(pendingPairingState.active(OWNER))

        // The QR is still on screen, so the same nonce must still accept an honest retry.
        assertTrue(session.onInboundBundle(encoded(otherBundle), proofFor(otherBundle, NONCE), REMOTE_HOST))

        assertIs<QrPairingEvent.VerifiedInbound>(events.last())
        assertNotNull(pendingPairingState.active(OWNER))
    }

    @Test
    fun `a proof keyed on another nonce fails`() = runTest {
        val events = collectEvents()
        session.register(NONCE, OWNER)

        assertFalse(session.onInboundBundle(encoded(scannerBundle), proofFor(scannerBundle, OTHER_NONCE), REMOTE_HOST))

        assertIs<QrPairingEvent.ProofFailed>(events.single())
        assertNull(pendingPairingState.active(OWNER))
    }

    @Test
    fun `a push with no proof at all falls back to the manual compare`() = runTest {
        val events = collectEvents()
        session.register(NONCE, OWNER)

        assertFalse(session.onInboundBundle(encoded(scannerBundle), null, REMOTE_HOST))

        val failure = assertIs<QrPairingEvent.ProofFailed>(events.single())
        assertEquals(ownBundle.safetyNumber(scannerBundle, fingerprintService), failure.safetyNumber)
        assertNull(pendingPairingState.active(OWNER))
    }

    @Test
    fun `an unarmed session ignores inbound pushes exactly as before QR pairing existed`() = runTest {
        val events = collectEvents()

        assertFalse(session.onInboundBundle(encoded(scannerBundle), proofFor(scannerBundle, NONCE), REMOTE_HOST))

        assertTrue(events.isEmpty())
        assertNull(pendingPairingState.active(OWNER))

        session.register(NONCE, OWNER)
        session.clear()
        assertFalse(session.onInboundBundle(encoded(scannerBundle), proofFor(scannerBundle, NONCE), REMOTE_HOST))

        assertTrue(events.isEmpty())
        assertNull(pendingPairingState.active(OWNER))
    }

    @Test
    fun `cancelling the ceremony takes the QR down with the pending exchange`() = runTest {
        val events = collectEvents()
        val cancel = CancelDevicePairing(pendingPairingState = pendingPairingState, qrPairingSession = session)
        session.register(NONCE, OWNER)

        cancel(Unit)

        assertFalse(session.onInboundBundle(encoded(scannerBundle), proofFor(scannerBundle, NONCE), REMOTE_HOST))
        assertTrue(events.isEmpty())
        assertNull(pendingPairingState.active(OWNER))
    }

    @Test
    fun `a verified proof consumes the nonce so the same push replayed is dropped`() = runTest {
        val events = collectEvents()
        session.register(NONCE, OWNER)
        val proof = proofFor(scannerBundle, NONCE)

        val first = session.onInboundBundle(encoded(scannerBundle), proof, REMOTE_HOST)
        // The nonce is gone by now, so this push cannot arm anything and must not claim it did —
        // a caller that spent an accept slot on it would be spending it on a replay.
        val second = session.onInboundBundle(encoded(scannerBundle), proof, "198.51.100.9")

        assertTrue(first)
        assertFalse(second)
        assertEquals(1, events.size)
        assertIs<QrPairingEvent.VerifiedInbound>(events.single())
        assertEquals(REMOTE_HOST, assertNotNull(pendingPairingState.active(OWNER)).peerAddress)
    }

    @Test
    fun `bundle bytes that are not a usable identity are dropped without a word`() = runTest {
        val events = collectEvents()
        session.register(NONCE, OWNER)

        assertFalse(
            session.onInboundBundle("not json at all".encodeToByteArray(), proofFor(scannerBundle, NONCE), REMOTE_HOST),
        )
        assertFalse(
            session.onInboundBundle(
                SHORT_KEY_BUNDLE_JSON.encodeToByteArray(),
                proofFor(scannerBundle, NONCE),
                REMOTE_HOST,
            ),
        )

        assertTrue(events.isEmpty())
        assertNull(pendingPairingState.active(OWNER))
    }

    @Test
    fun `a local identity this device cannot produce drops the push`() = runTest {
        val service = FakeFingerprintService(Outcome.Error("no identity", TransferFailure.GeneralTransferFailure))
        val state = PendingPairingState()
        val session = QrPairingSession(fingerprintService = service, pendingPairingState = state)
        val events = mutableListOf<QrPairingEvent>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { session.events.toList(events) }
        session.register(NONCE, OWNER)

        assertFalse(session.onInboundBundle(encoded(scannerBundle), proofFor(scannerBundle, NONCE), REMOTE_HOST))

        assertTrue(events.isEmpty())
        assertNull(state.active(OWNER))
    }

    @Test
    fun `an armed pairing belongs to the account that showed the QR and to no other`() = runTest {
        collectEvents()
        session.register(NONCE, OWNER)

        assertTrue(session.onInboundBundle(encoded(scannerBundle), proofFor(scannerBundle, NONCE), REMOTE_HOST))

        assertNull(pendingPairingState.active(OTHER_OWNER))
    }

    @Test
    fun `the armed pairing holds the re-encoded bundle, never the bytes that arrived on the wire`() = runTest {
        collectEvents()
        session.register(NONCE, OWNER)
        // Same bundle, differently shaped JSON. Storing the wire bytes would leave whatever parses
        // them next free to read something else out of them than this proof was verified over.
        val wireBytes = PRETTY_JSON.encodeToString(scannerBundle).encodeToByteArray()
        assertFalse(wireBytes.contentEquals(encoded(scannerBundle)), "the wire form must differ from the re-encoding")

        assertTrue(session.onInboundBundle(wireBytes, proofFor(scannerBundle, NONCE), REMOTE_HOST))

        val pending = assertNotNull(pendingPairingState.active(OWNER))
        assertContentEquals(encoded(scannerBundle), pending.peerBundleBytes)
    }

    @Test
    fun `register copies the nonce so a caller reusing its array cannot retire the live code`() = runTest {
        collectEvents()
        val callerNonce = NONCE.copyOf()
        val proof = proofFor(scannerBundle, callerNonce)
        session.register(callerNonce, OWNER)

        callerNonce.fill(0)

        assertTrue(session.onInboundBundle(encoded(scannerBundle), proof, REMOTE_HOST))
        assertNotNull(pendingPairingState.active(OWNER))
    }

    private fun TestScope.collectEvents(): List<QrPairingEvent> {
        val received = mutableListOf<QrPairingEvent>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { session.events.toList(received) }
        return received
    }

    private fun encoded(bundle: DeviceIdentityBundle): ByteArray =
        Json.encodeToString(bundle).encodeToByteArray()

    /** The scanner's half of the protocol: HMAC(nonce, canonical(scanner) || canonical(shower)). */
    private fun proofFor(peer: DeviceIdentityBundle, nonce: ByteArray): String =
        B64.encode(
            fingerprintService.hmacSha256(
                key = nonce,
                data = peer.canonicalEncoding() + ownBundle.canonicalEncoding(),
            ),
        )

    private fun bundle(fill: Byte): DeviceIdentityBundle = DeviceIdentityBundle(
        rsaSpki = byteArrayOf(fill),
        hybridPublicKey = hybridPublicKey(fill),
        mldsaPublicKey = ByteArray(1_952) { fill },
        capabilityBits = DeviceIdentityBundle.CAPABILITY_PASSWORDS,
    )

    private fun hybridPublicKey(fill: Byte): ByteArray = ByteArray(32 + 2 + 1_184) { fill }.also {
        it[32] = 0x04
        it[33] = 0xA0.toByte()
    }

    private companion object {
        val B64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)

        /** A second, equally valid shape for the same bundle, for the parser-differential test. */
        val PRETTY_JSON = Json { prettyPrint = true }
        val NONCE = ByteArray(32) { it.toByte() }
        val OTHER_NONCE = ByteArray(32) { (0x40 + it).toByte() }
        val OWNER = PairingOwner(account = "alice", session = "session-1")
        val OTHER_OWNER = PairingOwner(account = "bob", session = "session-2")
        const val REMOTE_HOST = "192.0.2.77"

        /** Well-formed JSON whose key lengths the identity bundle refuses on construction. */
        const val SHORT_KEY_BUNDLE_JSON =
            """{"rsaSpki":[1],"hybridPublicKey":[1,2],"mldsaPublicKey":[3],"capabilityBits":1}"""
    }
}

/**
 * Deterministic stand-in for the platform crypto seam.
 *
 * [digest] is a size-prefixed fold and [hmacSha256] is "digest the key, then the data" — both are
 * trivially forgeable and exist only so a test can predict the exact bytes the session compares. The
 * real primitives are pinned by the RFC 4231 known-answer test over `JvmFingerprintService`; nothing
 * here may stand in for that.
 */
private class FakeFingerprintService(
    private val own: Outcome<DeviceIdentityBundle>,
) : FingerprintService {
    override fun digest(bytes: ByteArray): ByteArray {
        val out = ByteArray(DIGEST_BYTES)
        out[0] = bytes.size.toByte()
        out[1] = (bytes.size ushr 8).toByte()
        bytes.forEachIndexed { index, byte ->
            val slot = 2 + index % (DIGEST_BYTES - 2)
            out[slot] = (out[slot] + byte + index).toByte()
        }
        return out
    }

    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray = digest(digest(key) + data)

    override fun randomBytes(count: Int): ByteArray = unused()

    override fun fingerprintOf(publicKeyBytes: ByteArray): String = unused()

    override suspend fun getOwnFingerprint(): Outcome<String> = unused()

    override suspend fun fetchPeerFingerprint(host: String, port: Int): Outcome<String> = unused()

    override suspend fun getOwnDeviceIdentityBundle(): Outcome<DeviceIdentityBundle> = own

    override suspend fun fetchPeerDeviceIdentityBundle(host: String, port: Int): Outcome<DeviceIdentityBundle> =
        unused()

    override suspend fun pushDeviceIdentityBundle(
        bundle: DeviceIdentityBundle,
        host: String,
        port: Int,
        proofBase64Url: String?,
    ): Outcome<Unit> = unused()

    private fun unused(): Nothing = error("the QR pairing session must not reach for this")

    private companion object {
        const val DIGEST_BYTES = 32
    }
}

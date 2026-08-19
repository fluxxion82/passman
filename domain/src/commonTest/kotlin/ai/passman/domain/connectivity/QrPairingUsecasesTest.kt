package ai.passman.domain.connectivity

import ai.passman.domain.base.invoke
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.PairingQrPayload
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.settings.model.ReconcileAction
import ai.passman.domain.settings.repository.TransferRepository
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

@OptIn(ExperimentalEncodingApi::class)
class GeneratePairingQrPayloadTest {
    private val fixture = QrPairingFixture()

    @Test
    fun `the code carries this device's address, its pairing port and its identity digest`() = runTest {
        val payload = assertIs<Outcome.Success<PairingQrPayload>>(fixture.generatePairingQrPayload()).value

        assertEquals(LOCAL_HOST, payload.host)
        assertEquals(PairingQrPayload.DEFAULT_PAIRING_PORT, payload.port)
        assertContentEquals(OWN_BUNDLE.digest(fixture.fingerprintService), payload.digest)
        assertEquals(NONCE_BYTES, payload.nonce.size)
    }

    @Test
    fun `the nonce in the code is the one an inbound proof is checked against`() = runTest {
        val payload = assertIs<Outcome.Success<PairingQrPayload>>(fixture.generatePairingQrPayload()).value

        val armed = fixture.pushFrom(SCANNER_BUNDLE, payload.nonce)

        assertTrue(armed, "the code the user is showing must be the one an honest scanner can answer")
        val pending = assertNotNull(fixture.pendingPairingState.active(OWNER))
        assertTrue(pending.verifiedViaQr)
    }

    @Test
    fun `the armed code belongs to the account that asked for it and to no other`() = runTest {
        val payload = assertIs<Outcome.Success<PairingQrPayload>>(fixture.generatePairingQrPayload()).value

        assertTrue(fixture.pushFrom(SCANNER_BUNDLE, payload.nonce))

        assertNotNull(fixture.pendingPairingState.active(OWNER), "the account that showed the code owns it")
        // Asked second on purpose: a foreign owner drops the entry, so this must not run first.
        assertNull(fixture.pendingPairingState.active(OTHER_OWNER))
    }

    @Test
    fun `a sign-in that lands mid-generate does not hand the code to the new account`() = runTest {
        // The switch happens while the identity fetch is in flight, so the owner is only the one
        // that asked for the code if it was sampled before that call suspended.
        val switching = QrPairingFixture(signsInDuringIdentityFetchAs = OTHER_OWNER)
        val payload = assertIs<Outcome.Success<PairingQrPayload>>(switching.generatePairingQrPayload()).value

        assertTrue(switching.pushFrom(SCANNER_BUNDLE, payload.nonce))

        assertNotNull(
            switching.pendingPairingState.active(OWNER),
            "the account that asked for the code owns it, whoever is signed in by the time it appears",
        )
    }

    @Test
    fun `showing the code again draws a fresh nonce and retires the old one`() = runTest {
        val first = assertIs<Outcome.Success<PairingQrPayload>>(fixture.generatePairingQrPayload()).value
        val second = assertIs<Outcome.Success<PairingQrPayload>>(fixture.generatePairingQrPayload()).value

        assertFalse(first.nonce.contentEquals(second.nonce), "each showing must key on its own nonce")
        assertFalse(fixture.pushFrom(SCANNER_BUNDLE, first.nonce), "the retired code must not still pair")
        assertTrue(fixture.pushFrom(SCANNER_BUNDLE, second.nonce))
    }

    @Test
    fun `a device with no network address is refused before anything is armed`() = runTest {
        val offline = QrPairingFixture(host = "")

        val outcome = assertIs<Outcome.Error>(offline.generatePairingQrPayload())

        assertEquals(TransferFailure.GeneralTransferFailure, outcome.cause)
        assertEquals(0, offline.fingerprintService.identityRequests, "the identity is not worth fetching yet")
        assertFalse(offline.pushFrom(SCANNER_BUNDLE, ANY_NONCE))
        assertNull(offline.pendingPairingState.active(OWNER))
    }

    @Test
    fun `an address that cannot be written into a code is refused instead of thrown`() = runTest {
        // Link-local IPv6 arrives from the platform with a zone suffix, and `%` is not a character
        // the payload's host allowlist accepts. A caller asked for an Outcome, not an exception.
        val scoped = QrPairingFixture(host = "fe80::1%en0")

        val outcome = assertIs<Outcome.Error>(scoped.generatePairingQrPayload())

        assertEquals(TransferFailure.GeneralTransferFailure, outcome.cause)
        assertFalse(scoped.pushFrom(SCANNER_BUNDLE, ANY_NONCE))
        assertNull(scoped.pendingPairingState.active(OWNER))
    }

    @Test
    fun `an identity this device cannot produce leaves no nonce armed`() = runTest {
        val failure = Outcome.Error("no identity", TransferFailure.PublicKeyFetchFailure)
        val broken = QrPairingFixture(ownIdentity = failure)

        assertSame(failure, broken.generatePairingQrPayload())

        assertFalse(broken.pushFrom(SCANNER_BUNDLE, ANY_NONCE))
        assertNull(broken.pendingPairingState.active(OWNER))
    }
}

@OptIn(ExperimentalEncodingApi::class)
class DismissPairingQrTest {
    private val fixture = QrPairingFixture()

    @Test
    fun `taking the code off screen stops the nonce behind it from pairing anything`() = runTest {
        val payload = assertIs<Outcome.Success<PairingQrPayload>>(fixture.generatePairingQrPayload()).value

        fixture.dismissPairingQr()

        assertFalse(fixture.pushFrom(SCANNER_BUNDLE, payload.nonce))
        assertNull(fixture.pendingPairingState.active(OWNER))
    }

    @Test
    fun `a pairing that was already verified survives the dialog closing`() = runTest {
        val payload = assertIs<Outcome.Success<PairingQrPayload>>(fixture.generatePairingQrPayload()).value
        assertTrue(fixture.pushFrom(SCANNER_BUNDLE, payload.nonce))

        // Closing the QR is exactly what the user does to read the confirm card underneath it.
        fixture.dismissPairingQr()

        val pending = assertNotNull(fixture.pendingPairingState.active(OWNER))
        assertTrue(pending.verifiedViaQr)
        assertEquals(REMOTE_HOST, pending.peerAddress)
    }
}

@OptIn(ExperimentalEncodingApi::class, ExperimentalCoroutinesApi::class)
class ObserveQrPairingEventsTest {
    private val fixture = QrPairingFixture()

    @Test
    fun `what the screen collects is what the pairing listener announced`() = runTest {
        val received = mutableListOf<QrPairingEvent>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) {
            fixture.observeQrPairingEvents().toList(received)
        }
        val payload = assertIs<Outcome.Success<PairingQrPayload>>(fixture.generatePairingQrPayload()).value

        assertTrue(fixture.pushFrom(SCANNER_BUNDLE, payload.nonce))

        val event = assertIs<QrPairingEvent.VerifiedInbound>(received.single())
        assertEquals(REMOTE_HOST, event.peerAddress)
        assertEquals(OWN_BUNDLE.safetyNumber(SCANNER_BUNDLE, fixture.fingerprintService), event.safetyNumber)
    }
}

@OptIn(ExperimentalEncodingApi::class)
class GetArmedQrPairingTest {
    private val fixture = QrPairingFixture()

    @Test
    fun `a QR-verified exchange armed for this account is handed back`() = runTest {
        val payload = assertIs<Outcome.Success<PairingQrPayload>>(fixture.generatePairingQrPayload()).value
        assertTrue(fixture.pushFrom(SCANNER_BUNDLE, payload.nonce))

        val pending = assertNotNull(fixture.getArmedQrPairing())

        assertTrue(pending.verifiedViaQr)
        assertEquals(REMOTE_HOST, pending.peerAddress)
    }

    @Test
    fun `an exchange from a manual ceremony is not one the compare can be skipped for`() = runTest {
        fixture.pendingPairingState.replace(
            PendingPairing(
                peerBundleBytes = fixture.encoded(SCANNER_BUNDLE),
                safetyNumber = "12345 67890 12345 67890 12345",
                peerAddress = REMOTE_HOST,
            ),
            OWNER,
        )

        assertNull(fixture.getArmedQrPairing())
    }

    @Test
    fun `nothing armed is nothing to report`() = runTest {
        assertNull(fixture.getArmedQrPairing())
    }
}

/**
 * The four QR pairing use-cases wired to a real [QrPairingSession] and [PendingPairingState].
 *
 * Only the platform seams are faked. Whether a generated code actually arms the session is the whole
 * question these tests ask, and a fake session could only ever answer it about itself.
 */
@OptIn(ExperimentalEncodingApi::class)
private class QrPairingFixture(
    host: String = LOCAL_HOST,
    ownIdentity: Outcome<DeviceIdentityBundle> = Outcome.Success(OWN_BUNDLE),
    signsInDuringIdentityFetchAs: PairingOwner? = null,
) {
    private val userPreferences = FakeUserPreferences(OWNER)
    val fingerprintService = FakeQrFingerprintService(ownIdentity) {
        signsInDuringIdentityFetchAs?.let(userPreferences::signInAs)
    }
    val pendingPairingState = PendingPairingState()
    val session = QrPairingSession(
        fingerprintService = fingerprintService,
        pendingPairingState = pendingPairingState,
    )
    private val transferRepository = FakeTransferRepository(host)

    val generatePairingQrPayload = GeneratePairingQrPayload(
        fingerprintService = fingerprintService,
        qrPairingSession = session,
        userPreferences = userPreferences,
        transferRepository = transferRepository,
    )
    val dismissPairingQr = DismissPairingQr(qrPairingSession = session)
    val observeQrPairingEvents = ObserveQrPairingEvents(qrPairingSession = session)
    val getArmedQrPairing = GetArmedQrPairing(
        pendingPairingState = pendingPairingState,
        userPreferences = userPreferences,
    )

    fun encoded(bundle: DeviceIdentityBundle): ByteArray = Json.encodeToString(bundle).encodeToByteArray()

    /** The scanner's half of the ceremony: a push proving it holds [nonce]. */
    suspend fun pushFrom(peer: DeviceIdentityBundle, nonce: ByteArray): Boolean = session.onInboundBundle(
        bundleBytes = encoded(peer),
        proofBase64Url = B64.encode(
            fingerprintService.hmacSha256(
                key = nonce,
                data = peer.canonicalEncoding() + OWN_BUNDLE.canonicalEncoding(),
            ),
        ),
        remoteHost = REMOTE_HOST,
    )
}

/**
 * Answers the two things [PairingOwner.current] samples; everything else fails loudly.
 *
 * [signInAs] is how a test moves the signed-in account underneath a use-case that is already
 * running, which is what an account switch looks like from a suspending call's point of view.
 */
private class FakeUserPreferences(private var owner: PairingOwner) : UserPreferences {
    fun signInAs(next: PairingOwner) {
        owner = next
    }

    override suspend fun getUser(): AppUser =
        owner.account?.let { AppUser.LoggedIn(it, Password("hash", "salt")) } ?: AppUser.Anonymous

    override suspend fun getSessionId(): String = owner.session

    override suspend fun upsert(user: AppUser): Unit = unused("upsert")
    override suspend fun getStoredCredentials(username: String): Password? = unused("getStoredCredentials")
    override suspend fun getUserState(): UserState? = unused("getUserState")
    override suspend fun setUserState(state: UserState): Unit = unused("setUserState")
    override suspend fun clear(): Unit = unused("clear")

    private fun unused(name: String): Nothing = error("the QR pairing use-cases must not reach for $name")
}

/** Only [getIpAddress] is part of this feature's contract; the rest of the transport is not. */
private class FakeTransferRepository(private val ipAddress: String) : TransferRepository {
    override suspend fun getIpAddress(): String = ipAddress

    override val peerHandshakeComplete: StateFlow<Boolean> = MutableStateFlow(false)
    override suspend fun startTransferServer(): Unit = unused("startTransferServer")
    override suspend fun stopTransferServer(): Unit = unused("stopTransferServer")
    override suspend fun isTransferServerRunning(): Boolean = unused("isTransferServerRunning")
    override suspend fun startPairingServer(): Unit = unused("startPairingServer")
    override suspend fun stopPairingServer(): Unit = unused("stopPairingServer")
    override suspend fun executeReconcileAction(reconcileAction: ReconcileAction): Outcome<Unit> =
        unused("executeReconcileAction")

    private fun unused(name: String): Nothing = error("the QR pairing use-cases must not reach for $name")
}

/**
 * Deterministic stand-in for the platform crypto seam, matching `QrPairingSessionTest`'s: [digest] is
 * a size-prefixed fold and [hmacSha256] is "digest the key, then the data". Both are trivially
 * forgeable and exist only so a test can predict the bytes. [randomBytes] advances on every draw so a
 * use-case that reused one nonce across two showings could not pass.
 */
private class FakeQrFingerprintService(
    private val own: Outcome<DeviceIdentityBundle>,
    private val onIdentityFetch: () -> Unit = {},
) : FingerprintService {
    var identityRequests: Int = 0
        private set
    private var draws = 0

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

    override fun randomBytes(count: Int): ByteArray {
        draws++
        return ByteArray(count) { (draws * 31 + it).toByte() }
    }

    override suspend fun getOwnDeviceIdentityBundle(): Outcome<DeviceIdentityBundle> {
        identityRequests++
        // Stands in for whatever a real suspending fetch lets happen while it is in flight.
        onIdentityFetch()
        return own
    }

    override fun fingerprintOf(publicKeyBytes: ByteArray): String = unused("fingerprintOf")
    override suspend fun getOwnFingerprint(): Outcome<String> = unused("getOwnFingerprint")
    override suspend fun fetchPeerFingerprint(host: String, port: Int): Outcome<String> = unused("fetchPeerFingerprint")
    override suspend fun fetchPeerDeviceIdentityBundle(host: String, port: Int): Outcome<DeviceIdentityBundle> =
        unused("fetchPeerDeviceIdentityBundle")

    override suspend fun pushDeviceIdentityBundle(
        bundle: DeviceIdentityBundle,
        host: String,
        port: Int,
        proofBase64Url: String?,
    ): Outcome<Unit> = unused("pushDeviceIdentityBundle")

    private fun unused(name: String): Nothing = error("the QR pairing use-cases must not reach for $name")

    private companion object {
        const val DIGEST_BYTES = 32
    }
}

@OptIn(ExperimentalEncodingApi::class)
private val B64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
private const val NONCE_BYTES = 32
private const val LOCAL_HOST = "192.0.2.10"
private const val REMOTE_HOST = "192.0.2.77"
private val OWNER = PairingOwner(account = "alice", session = "session-1")
private val OTHER_OWNER = PairingOwner(account = "bob", session = "session-2")
private val ANY_NONCE = ByteArray(NONCE_BYTES) { it.toByte() }
private val OWN_BUNDLE = testBundle(0x11)
private val SCANNER_BUNDLE = testBundle(0x22)

private fun testBundle(fill: Byte): DeviceIdentityBundle = DeviceIdentityBundle(
    rsaSpki = byteArrayOf(fill),
    hybridPublicKey = ByteArray(32 + 2 + 1_184) { fill }.also {
        it[32] = 0x04
        it[33] = 0xA0.toByte()
    },
    mldsaPublicKey = ByteArray(1_952) { fill },
    capabilityBits = DeviceIdentityBundle.CAPABILITY_PASSWORDS,
)

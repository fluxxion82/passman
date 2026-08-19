package ai.passman.domain.connectivity

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.model.PairingQrPayload
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * The scanner's half of QR pairing: the ceremony run by the device that read someone else's code.
 *
 * Two things separate it from the manual ceremony, and both are asked about here. The code commits
 * to an identity, so the bundle fetched from the address in it must digest to what the code said or
 * the ceremony stops before this device tells that address anything about itself. And the scan is
 * proved to the peer by an HMAC keyed on the nonce only the code carried, over both canonical
 * bundles in a frozen order — scanner's own first, the fetched one second — which is the same byte
 * sequence [QrPairingSession] rebuilds from the other side.
 */
@OptIn(ExperimentalEncodingApi::class)
class BeginDevicePairingTest {
    private val fingerprintService = FakeScannerFingerprintService(own = SCANNER_BUNDLE, peer = SHOWER_BUNDLE)
    private val pendingPairingState = PendingPairingState()
    private val beginDevicePairing = BeginDevicePairing(
        fingerprintService = fingerprintService,
        pendingPairingState = pendingPairingState,
        userPreferences = FakeScannerUserPreferences(OWNER),
    )

    @Test
    fun `a code that commits to the device at that address pairs and proves the scan`() = runTest {
        val outcome = assertIs<Outcome.Success<PendingPairing>>(
            beginDevicePairing(BeginDevicePairing.Parameters(host = SHOWER_HOST, qr = codeFor(SHOWER_BUNDLE))),
        )

        val push = assertNotNull(fingerprintService.lastPush)
        assertEquals(SHOWER_HOST, push.host)
        assertEquals(PairingQrPayload.DEFAULT_PAIRING_PORT, push.port)
        assertEquals(expectedProof(), push.proofBase64Url)
        assertTrue(outcome.value.verifiedViaQr, "a scanned ceremony carries its own verification")
        assertEquals(SHOWER_HOST, outcome.value.peerAddress)
        val pending = assertNotNull(pendingPairingState.active(OWNER))
        assertTrue(pending.verifiedViaQr)
    }

    @Test
    fun `a code that commits to another device is refused before anything is pushed`() = runTest {
        val outcome = assertIs<Outcome.Error>(
            beginDevicePairing(BeginDevicePairing.Parameters(host = SHOWER_HOST, qr = codeFor(IMPOSTOR_BUNDLE))),
        )

        assertContains(outcome.message, "QR does not match")
        assertEquals(TransferFailure.GeneralTransferFailure, outcome.cause)
        // The identity at that address is not the one the user scanned, so it learns nothing about
        // this device — and nothing is armed for a Confirm press to spend.
        assertEquals(0, fingerprintService.pushes, "a mismatched commitment must not reach the push")
        assertNull(pendingPairingState.active(OWNER))
    }

    @Test
    fun `a ceremony no code started pushes no proof and still asks for the compare`() = runTest {
        val outcome = assertIs<Outcome.Success<PendingPairing>>(
            beginDevicePairing(BeginDevicePairing.Parameters(host = SHOWER_HOST)),
        )

        assertNull(assertNotNull(fingerprintService.lastPush).proofBase64Url, "no scan, no possession to prove")
        assertFalse(outcome.value.verifiedViaQr)
        assertFalse(assertNotNull(pendingPairingState.active(OWNER)).verifiedViaQr)
    }

    @Test
    fun `a ceremony aimed somewhere other than the scanned code's own address is a programmer error`() = runTest {
        val code = codeFor(SHOWER_BUNDLE)

        // Digesting a commitment the code made about one machine while talking to another verifies
        // nothing about the machine on the other end, so the two must never be allowed to drift.
        assertFailsWith<IllegalArgumentException> {
            beginDevicePairing(BeginDevicePairing.Parameters(host = SCANNER_HOST, qr = code))
        }
        assertFailsWith<IllegalArgumentException> {
            beginDevicePairing(
                BeginDevicePairing.Parameters(
                    host = SHOWER_HOST,
                    port = PairingQrPayload.DEFAULT_PAIRING_PORT + 1,
                    qr = code,
                ),
            )
        }

        assertEquals(0, fingerprintService.pushes)
        assertNull(pendingPairingState.active(OWNER))
    }

    @Test
    fun `a push the peer refused fails the ceremony and arms nothing`() = runTest {
        val refusal = Outcome.Error("peer refused the bundle", TransferFailure.GeneralTransferFailure)
        fingerprintService.pushOutcome = refusal

        val outcome = assertIs<Outcome.Error>(
            beginDevicePairing(BeginDevicePairing.Parameters(host = SHOWER_HOST, qr = codeFor(SHOWER_BUNDLE))),
        )

        // The peer never heard this device out, so there is no exchange for a Confirm press to
        // spend — the failure must surface as itself rather than as a pairing waiting to be trusted.
        assertEquals(refusal.message, outcome.message)
        assertEquals(refusal.cause, outcome.cause)
        assertNull(pendingPairingState.active(OWNER))
    }

    @Test
    fun `the proof this side sends is the one the device showing the code checks for`() = runTest {
        assertIs<Outcome.Success<PendingPairing>>(
            beginDevicePairing(BeginDevicePairing.Parameters(host = SHOWER_HOST, qr = codeFor(SHOWER_BUNDLE))),
        )
        val showerState = PendingPairingState()
        val shower = QrPairingSession(
            fingerprintService = FakeScannerFingerprintService(own = SHOWER_BUNDLE, peer = SCANNER_BUNDLE),
            pendingPairingState = showerState,
        )
        shower.register(NONCE, OWNER)

        val armed = shower.onInboundBundle(
            bundleBytes = Json.encodeToString(SCANNER_BUNDLE).encodeToByteArray(),
            proofBase64Url = assertNotNull(fingerprintService.lastPush).proofBase64Url,
            remoteHost = SCANNER_HOST,
        )

        assertTrue(armed, "the proof order is frozen: the scanner's own bundle first, the fetched one second")
        assertTrue(assertNotNull(showerState.active(OWNER)).verifiedViaQr)
    }

    /** A code as the peer would have shown it: its own identity digest, plus the nonce behind it. */
    private fun codeFor(shown: DeviceIdentityBundle): PairingQrPayload = PairingQrPayload(
        host = SHOWER_HOST,
        port = PairingQrPayload.DEFAULT_PAIRING_PORT,
        digest = shown.digest(fingerprintService),
        nonce = NONCE,
    )

    private fun expectedProof(): String = B64.encode(
        fingerprintService.hmacSha256(
            key = NONCE,
            data = SCANNER_BUNDLE.canonicalEncoding() + SHOWER_BUNDLE.canonicalEncoding(),
        ),
    )

    private companion object {
        val B64 = Base64.UrlSafe.withPadding(Base64.PaddingOption.ABSENT)
        val NONCE = ByteArray(32) { (0x50 + it).toByte() }
        val OWNER = PairingOwner(account = "alice", session = "session-1")
        const val SHOWER_HOST = "192.0.2.77"
        const val SCANNER_HOST = "192.0.2.10"
        val SCANNER_BUNDLE = scannerTestBundle(0x11)
        val SHOWER_BUNDLE = scannerTestBundle(0x22)
        val IMPOSTOR_BUNDLE = scannerTestBundle(0x33)

        fun scannerTestBundle(fill: Byte): DeviceIdentityBundle = DeviceIdentityBundle(
            rsaSpki = byteArrayOf(fill),
            hybridPublicKey = ByteArray(32 + 2 + 1_184) { fill }.also {
                it[32] = 0x04
                it[33] = 0xA0.toByte()
            },
            mldsaPublicKey = ByteArray(1_952) { fill },
            capabilityBits = DeviceIdentityBundle.CAPABILITY_PASSWORDS,
        )
    }
}

/**
 * The pairing seam as the scanner uses it: a peer identity to fetch, a local one to push, and the
 * deterministic [digest]/[hmacSha256] stand-ins the other QR tests use, so a test can predict the
 * exact proof bytes. The real primitives are pinned by the RFC 4231 known-answer test over
 * `JvmFingerprintService`; nothing here may stand in for that.
 */
private class FakeScannerFingerprintService(
    private val own: DeviceIdentityBundle,
    private val peer: DeviceIdentityBundle,
) : FingerprintService {
    /** Exactly what the ceremony handed the transport, so a test can read the proof off the wire. */
    class Push(
        val bundle: DeviceIdentityBundle,
        val host: String,
        val port: Int,
        val proofBase64Url: String?,
    )

    var pushes: Int = 0
        private set
    var lastPush: Push? = null
        private set

    /** What the transport makes of the push; set to an error to play a peer that refused it. */
    var pushOutcome: Outcome<Unit> = Outcome.Success(Unit)

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

    override suspend fun getOwnDeviceIdentityBundle(): Outcome<DeviceIdentityBundle> = Outcome.Success(own)

    override suspend fun fetchPeerDeviceIdentityBundle(host: String, port: Int): Outcome<DeviceIdentityBundle> =
        Outcome.Success(peer)

    override suspend fun pushDeviceIdentityBundle(
        bundle: DeviceIdentityBundle,
        host: String,
        port: Int,
        proofBase64Url: String?,
    ): Outcome<Unit> {
        pushes++
        lastPush = Push(bundle = bundle, host = host, port = port, proofBase64Url = proofBase64Url)
        return pushOutcome
    }

    override fun randomBytes(count: Int): ByteArray = unused("randomBytes")
    override fun fingerprintOf(publicKeyBytes: ByteArray): String = unused("fingerprintOf")
    override suspend fun getOwnFingerprint(): Outcome<String> = unused("getOwnFingerprint")
    override suspend fun fetchPeerFingerprint(host: String, port: Int): Outcome<String> = unused("fetchPeerFingerprint")

    private fun unused(name: String): Nothing = error("the pairing ceremony must not reach for $name")

    private companion object {
        const val DIGEST_BYTES = 32
    }
}

/** Answers only the two things [PairingOwner.current] samples; everything else fails loudly. */
private class FakeScannerUserPreferences(private val owner: PairingOwner) : UserPreferences {
    override suspend fun getUser(): AppUser =
        owner.account?.let { AppUser.LoggedIn(it, Password("hash", "salt")) } ?: AppUser.Anonymous

    override suspend fun getSessionId(): String = owner.session

    override suspend fun upsert(user: AppUser): Unit = unused("upsert")
    override suspend fun getStoredCredentials(username: String): Password? = unused("getStoredCredentials")
    override suspend fun getUserState(): UserState? = unused("getUserState")
    override suspend fun setUserState(state: UserState): Unit = unused("setUserState")
    override suspend fun clear(): Unit = unused("clear")

    private fun unused(name: String): Nothing = error("the pairing ceremony must not reach for $name")
}

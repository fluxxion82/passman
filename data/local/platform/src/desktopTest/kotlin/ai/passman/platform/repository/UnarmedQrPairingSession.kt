package ai.passman.platform.repository

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.PendingPairingState
import ai.passman.domain.connectivity.QrPairingSession
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.service.FingerprintService

/**
 * A [QrPairingSession] with no QR ever shown, for the [FileTransferRepository] tests that are not
 * about pairing.
 *
 * An unarmed session drops an inbound push before it consults anything, so the seam below never
 * runs — and it throws rather than answering, which is the assertion: a test that starts routing
 * pairing traffic through this fixture finds out instead of quietly pairing against a stub.
 */
internal fun unarmedQrPairingSession(): QrPairingSession =
    QrPairingSession(fingerprintService = NoFingerprints, pendingPairingState = PendingPairingState())

private object NoFingerprints : FingerprintService {
    override fun digest(bytes: ByteArray): ByteArray = unused()
    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray = unused()
    override fun randomBytes(count: Int): ByteArray = unused()
    override fun fingerprintOf(publicKeyBytes: ByteArray): String = unused()
    override suspend fun getOwnFingerprint(): Outcome<String> = unused()
    override suspend fun fetchPeerFingerprint(host: String, port: Int): Outcome<String> = unused()
    override suspend fun getOwnDeviceIdentityBundle(): Outcome<DeviceIdentityBundle> = unused()
    override suspend fun fetchPeerDeviceIdentityBundle(host: String, port: Int): Outcome<DeviceIdentityBundle> =
        unused()

    override suspend fun pushDeviceIdentityBundle(
        bundle: DeviceIdentityBundle,
        host: String,
        port: Int,
        proofBase64Url: String?,
    ): Outcome<Unit> = unused()

    private fun unused(): Nothing = error("this fixture shows no QR and must not reach the pairing seam")
}

package ai.passman.platform.connectivity

import ai.passman.crypto.CryptoKey
import ai.passman.crypto.CryptoService
import ai.passman.domain.connectivity.PairingOwner
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.initialization.models.UserState
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.models.Password
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.repo.Platform
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlinx.coroutines.flow.Flow

/**
 * The two primitives behind QR pairing — the possession proof's HMAC and the nonce's randomness —
 * are stateless platform calls, so they are pinned against the standard vector rather than against
 * a session. Every collaborator below refuses to answer: reaching one from these methods is a bug,
 * not a missing fake.
 */
class JvmFingerprintServiceCryptoTest {
    @Test
    fun `hmacSha256 matches RFC 4231 test case 2`() {
        val mac = service().hmacSha256(
            key = "Jefe".encodeToByteArray(),
            data = "what do ya want for nothing?".encodeToByteArray(),
        )

        assertEquals(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            mac.joinToString("") { "%02x".format(it.toInt() and 0xFF) },
        )
    }

    @Test
    fun `randomBytes returns the requested count and does not repeat itself`() {
        val service = service()

        val first = service.randomBytes(32)
        val second = service.randomBytes(32)

        assertEquals(32, first.size)
        assertEquals(32, second.size)
        assertFalse(
            first.contentEquals(second),
            "two nonces drawn from the same service must differ — a fixed or unfilled buffer would " +
                "let a replayed QR pass its possession proof",
        )
    }

    /** The service over collaborators only its session-bound members are allowed to touch. */
    private fun service() = JvmFingerprintService(
        userPreferences = UnusedUserPreferences,
        hybridKeyManager = HybridKeyManager(
            platform = UnusedPlatform,
            cryptoService = UnusedCryptoService,
            userPreferences = UnusedUserPreferences,
            trustedDevices = UnusedTrustedDevicesRepository,
        ),
        mlDsaKeyManager = MlDsaKeyManager(
            platform = UnusedPlatform,
            cryptoService = UnusedCryptoService,
            userPreferences = UnusedUserPreferences,
            trustedDevices = UnusedTrustedDevicesRepository,
        ),
    )
}

private fun unused(): Nothing = error("hmacSha256 and randomBytes must not touch the session")

private object UnusedPlatform : Platform() {
    override fun getLocalPath(): String = unused()
}

private object UnusedCryptoService : CryptoService {
    override fun encryptBytes(plain: ByteArray, publicKey: CryptoKey): ByteArray = unused()
    override fun decryptBytes(cipher: ByteArray, privateKey: CryptoKey): ByteArray = unused()
}

private object UnusedUserPreferences : UserPreferences {
    override suspend fun getUser(): AppUser = unused()
    override suspend fun upsert(user: AppUser) = unused()
    override suspend fun getStoredCredentials(username: String): Password? = unused()
    override suspend fun getUserState(): UserState? = unused()
    override suspend fun setUserState(state: UserState) = unused()
    override suspend fun getSessionId(): String = unused()
    override suspend fun clear() = unused()
}

private object UnusedTrustedDevicesRepository : TrustedDevicesRepository {
    override fun observeAll(): Flow<List<TrustedDevice>> = unused()
    override suspend fun getAll(): List<TrustedDevice> = unused()
    override suspend fun add(device: TrustedDevice, expectedOwner: PairingOwner): Boolean = unused()
    override suspend fun remove(name: String) = unused()
    override suspend fun getByHost(host: String): TrustedDevice? = unused()
    override suspend fun updateLastSync(name: String, host: String, timestampMs: Long) = unused()
    override suspend fun updateHost(name: String, host: String) = unused()
    override suspend fun updateAllowedOps(name: String, allowedOps: Set<String>) = unused()
    override suspend fun markSignedHybridPairingsForReverification() = unused()
}

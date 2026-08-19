package ai.passman.platform.connectivity

import ai.passman.cache.di.passmanSessionScope
import ai.passman.crypto.CryptoKey
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY_HANDLE
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.DeviceIdentityBundle
import ai.passman.domain.connectivity.service.FingerprintService
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.user.repository.UserPreferences
import com.k2k.test.client.downloadFile
import com.k2k.test.client.downloadPairingBundle
import com.k2k.test.client.uploadPairingBundle
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.koin.core.qualifier.named

class JvmFingerprintService(
    private val userPreferences: UserPreferences,
    private val hybridKeyManager: HybridKeyManager,
    private val mlDsaKeyManager: MlDsaKeyManager,
) : FingerprintService {
    private val json = Json

    // One seeded instance for the process: SecureRandom seeds itself from the OS on first use, and
    // constructing a fresh one per nonce pays that cost again for no extra entropy.
    private val secureRandom = SecureRandom()

    override fun digest(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    override fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray =
        Mac.getInstance(HMAC_SHA256)
            .apply { init(SecretKeySpec(key, HMAC_SHA256)) }
            .doFinal(data)

    override fun randomBytes(count: Int): ByteArray = ByteArray(count).also(secureRandom::nextBytes)

    override fun fingerprintOf(publicKeyBytes: ByteArray): String {
        return digest(publicKeyBytes).joinToString(":") { byte -> "%02X".format(byte.toInt() and 0xFF) }
    }

    override suspend fun getOwnFingerprint(): Outcome<String> = runCatching {
        val fingerprint = passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val publicKey: CryptoKey = scope.get(named(PUBLIC_ENCRYPTION_KEY_HANDLE))
            fingerprintOf(publicKey.encoded)
        }
        if (fingerprint != null) {
            Outcome.Success(fingerprint)
        } else {
            Outcome.Error(
                "session scope unavailable - sign in first",
                TransferFailure.GeneralTransferFailure,
            )
        }
    }.getOrElse {
        Outcome.Error(
            "failed to compute own fingerprint: ${it.message}",
            TransferFailure.GeneralTransferFailure,
        )
    }

    // Plaintext fetch against the peer's pairing port (no tls arg) — this is the one bootstrap
    // step with no pin yet. The TLS-only data server (2323) would refuse it.
    override suspend fun fetchPeerFingerprint(host: String, port: Int): Outcome<String> = runCatching {
        val pubkey = downloadFile("publicKey", host, port)
            ?: return Outcome.Error("public key is null", TransferFailure.PublicKeyFetchFailure)
        Outcome.Success(fingerprintOf(pubkey))
    }.getOrElse {
        when (it) {
            is ConnectException, is SocketTimeoutException ->
                Outcome.Error("peer unreachable: ${it.message}", TransferFailure.PeerUnreachable(host))
            else ->
                Outcome.Error("failed to fetch fingerprint: ${it.message}", TransferFailure.GeneralTransferFailure)
        }
    }

    override suspend fun getOwnDeviceIdentityBundle(): Outcome<DeviceIdentityBundle> = runCatching {
        val bundle = passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val rsaPublicKey: CryptoKey = scope.get(named(PUBLIC_ENCRYPTION_KEY_HANDLE))
            val hybridPublicKey = hybridKeyManager.getPublicKeySerialized()
                ?: error("hybrid public key unavailable")
            val mldsaPublicKey = mlDsaKeyManager.getPublicKeySerialized()
                ?: error("ML-DSA public key unavailable")
            DeviceIdentityBundle.local(
                rsaSpki = rsaPublicKey.encoded,
                hybridPublicKey = hybridPublicKey,
                mldsaPublicKey = mldsaPublicKey,
            )
        }
        bundle?.let { Outcome.Success(it) } ?: Outcome.Error(
            "session scope unavailable - sign in first",
            TransferFailure.GeneralTransferFailure,
        )
    }.getOrElse {
        Outcome.Error(
            "failed to build local pairing identity: ${it.message}",
            TransferFailure.GeneralTransferFailure,
        )
    }

    override suspend fun fetchPeerDeviceIdentityBundle(host: String, port: Int): Outcome<DeviceIdentityBundle> = runCatching {
        val bytes = downloadPairingBundle(host, port)
            ?: return Outcome.Error("peer pairing bundle is unavailable", TransferFailure.PublicKeyFetchFailure)
        Outcome.Success(json.decodeFromString<DeviceIdentityBundle>(bytes.decodeToString()))
    }.getOrElse {
        when (it) {
            is ConnectException, is SocketTimeoutException ->
                Outcome.Error("peer unreachable: ${it.message}", TransferFailure.PeerUnreachable(host))
            else -> Outcome.Error(
                "failed to fetch pairing bundle: ${it.message}",
                TransferFailure.GeneralTransferFailure,
            )
        }
    }

    override suspend fun pushDeviceIdentityBundle(
        bundle: DeviceIdentityBundle,
        host: String,
        port: Int,
        proofBase64Url: String?,
    ): Outcome<Unit> = runCatching {
        // The proof rides as a header rather than inside the bundle: the bundle is the frozen
        // identity document both sides digest, and a peer that never showed a QR simply never reads
        // the header. A ceremony no code started passes null and the push is byte-identical to what
        // every previous version sent.
        uploadPairingBundle(
            json.encodeToString(bundle).encodeToByteArray(),
            host,
            port,
            pairingProof = proofBase64Url,
        )
        Outcome.Success(Unit)
    }.getOrElse {
        when (it) {
            is ConnectException, is SocketTimeoutException ->
                Outcome.Error("peer unreachable: ${it.message}", TransferFailure.PeerUnreachable(host))
            else -> Outcome.Error(
                "failed to push pairing bundle: ${it.message}",
                TransferFailure.GeneralTransferFailure,
            )
        }
    }

    private companion object {
        const val HMAC_SHA256 = "HmacSHA256"
    }
}

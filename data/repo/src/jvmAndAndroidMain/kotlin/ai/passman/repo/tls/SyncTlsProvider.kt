package ai.passman.repo.tls

import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.user.repository.UserPreferences
import com.k2k.test.tls.K2kClientTls
import com.k2k.test.tls.K2kServerTls
import java.security.Key
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import org.koin.core.qualifier.named
import org.koin.mp.KoinPlatform

/**
 * Single source of the mutual-TLS material for LAN sync. Both the receive server
 * ([FileTransferRepository]) and the client transfer services build their [K2kServerTls] /
 * [K2kClientTls] here so the session-key lookup and pin resolution live in exactly one place.
 *
 * The keystore is minted per call from the in-session identity key (see [TlsIdentity]); the raw
 * login password isn't available at sync time so we cannot reload the on-disk `.pfx`. The keystore
 * password is a throwaway in-memory value — it never leaves the process and guards nothing at rest.
 */
class SyncTlsProvider(
    private val userPreferences: UserPreferences,
    private val trustedDevices: TrustedDevicesRepository,
) {
    private suspend fun sessionKeyStore(): KeyStore? {
        val scope = KoinPlatform.getKoin().getOrCreateScope(
            "session-${userPreferences.getSessionId()}",
            named("sessionScope"),
        )
        val privateKey = scope.getOrNull<Key>(named(PRIVATE_DECRYPTION_KEY)) as? PrivateKey ?: return null
        val publicKey = scope.getOrNull<Key>(named(PUBLIC_ENCRYPTION_KEY)) as? PublicKey ?: return null
        return TlsIdentity.buildSessionKeyStore(privateKey, publicKey, KEYSTORE_PASSWORD)
    }

    /**
     * Server TLS for the data port: presents this device's cert and only admits clients whose
     * cert SPKI pins to a paired device. Empty pin set (no paired devices) fails closed. Returns
     * null when the session keys aren't available (not signed in) — caller should stay plaintext-off.
     */
    suspend fun serverTls(): K2kServerTls? {
        val keyStore = sessionKeyStore() ?: return null
        val pins = trustedDevices.getAll()
            .map { TlsIdentity.fingerprintToPin(it.fingerprint) }
            .toSet()
        return K2kServerTls(keyStore, KEYSTORE_PASSWORD, TlsIdentity.ALIAS, pins)
    }

    /**
     * The paired device whose frozen RSA SPKI pin matches the caller's verified TLS [pin], or null
     * for an unknown or absent pin. This is how the receive side learns *which* authenticated device
     * sent a payload — the k2k handlers thread the pin through, and everything the signed-hybrid
     * policy decides is keyed on the device resolved here.
     */
    suspend fun deviceForPin(pin: String?): TrustedDevice? {
        if (pin == null) return null
        return trustedDevices.getAll().firstOrNull {
            TlsIdentity.fingerprintToPin(it.fingerprint) == pin
        }
    }

    /** The paired device record at [host], if any. Sender-side policy dispatches on this record. */
    suspend fun deviceForHost(host: String): TrustedDevice? = trustedDevices.getByHost(host)

    /**
     * Per-operation authorization for an inbound connection, keyed by the caller's verified SPKI
     * [pin]. Returns true only when a paired device matches [pin], its pairing is in a state that
     * may sync at all, and its `allowedOps` include [op]. The TLS layer already refused unpinned
     * callers; this narrows which op each paired device may do (e.g. a password-only device is
     * denied `pgp-keys`). Unknown pin / null -> deny.
     */
    suspend fun authorize(op: String, pin: String?): Boolean {
        val device = deviceForPin(pin) ?: return false
        // Exhaustive on purpose: a fourth PairingSecurity value must fail compilation here, not
        // silently inherit either behaviour. AwaitingConfirmation is denied everything — including
        // the public-key downloads — until the user re-confirms the safety number.
        val pairingMaySync = when (device.pairingSecurity) {
            PairingSecurity.LegacyRsa, PairingSecurity.SignedHybridRequired -> true
            PairingSecurity.AwaitingConfirmation -> false
        }
        if (!pairingMaySync) return false
        // Any syncable paired device may fetch this device's public key material (required for every
        // sync op); all other downloads and ops fall through to the per-device allowlist.
        return op in PUBLIC_KEY_DOWNLOAD_OPS || op in device.allowedOps
    }

    /**
     * Client TLS for talking to [host]: presents this device's cert and pins the server to the
     * stored fingerprint of the trusted device at [host]. Returns null when [host] isn't a paired
     * device (unknown host — deny), the pairing awaits re-verification (its keys are not currently
     * trustworthy in either direction), or the session keys aren't available.
     */
    suspend fun clientTls(host: String): K2kClientTls? {
        val device = trustedDevices.getByHost(host) ?: return null
        val pairingMaySync = when (device.pairingSecurity) {
            PairingSecurity.LegacyRsa, PairingSecurity.SignedHybridRequired -> true
            PairingSecurity.AwaitingConfirmation -> false
        }
        if (!pairingMaySync) return null
        val keyStore = sessionKeyStore() ?: return null
        return K2kClientTls(
            keyStore,
            KEYSTORE_PASSWORD,
            TlsIdentity.ALIAS,
            setOf(TlsIdentity.fingerprintToPin(device.fingerprint)),
        )
    }

    private companion object {
        // In-memory only; guards the throwaway session keystore, never persisted.
        val KEYSTORE_PASSWORD = "passman-session-tls".toCharArray()

        // The k2k server scopes kind-less downloads as "download/<fileName>"; only these two names
        // (this device's classical, hybrid, and ML-DSA public keys) are fetchable by any paired device.
        val PUBLIC_KEY_DOWNLOAD_OPS = setOf("download/publicKey", "download/hybridPublicKey", "download/mldsaPublicKey")
    }
}

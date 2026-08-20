package ai.passman.repo.tls

import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY
import ai.passman.repo.di.PUBLIC_ENCRYPTION_KEY
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.logging.KLogger
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
     * Every paired device whose frozen RSA SPKI pin matches the caller's verified TLS [pin].
     *
     * Normally none or one. More than one is reachable: re-pairing the same physical peer under a
     * new name leaves two records holding the same fingerprint, since the fingerprint is that
     * device's long-term identity and not a property of the pairing ceremony. Exposed as a list so
     * callers can tell "nobody" from "several", which need different answers and very different
     * error messages.
     */
    suspend fun devicesForPin(pin: String?): List<TrustedDevice> {
        if (pin == null) return emptyList()
        return trustedDevices.getAll().filter {
            TlsIdentity.fingerprintToPin(it.fingerprint) == pin
        }
    }

    /**
     * The single paired device behind [pin], or null when no pairing matches — or when more than
     * one does.
     *
     * One match or nothing, never a first match. What this returns is not a label: it selects the
     * inbound decryption policy and the per-op allowlist, so with two records sharing a fingerprint
     * an arbitrary winner meant an inbound payload could be accepted as `LegacyRsa` while the other
     * record demanded a signed hybrid envelope — a silent downgrade of the exact boundary pairing
     * exists to hold — or granted an op the other record's `allowedOps` refused.
     *
     * Refusing is the fail-closed reading and the recoverable one: the records genuinely disagree
     * about policy and nothing here can say which is authoritative, whereas the user can delete the
     * duplicate pairing. It also matches
     * [ai.passman.domain.connectivity.repository.TrustedDevicesRepository.getByHost], so ambiguity
     * means the same thing whichever direction a session is running in.
     */
    suspend fun deviceForPin(pin: String?): TrustedDevice? {
        val matches = devicesForPin(pin)
        if (matches.size > 1) {
            // The pin is not logged: it is the peer's identity on the wire.
            KLogger.w {
                "${matches.size} pairings share the caller's fingerprint; refusing rather than " +
                    "choosing one of them - remove the duplicate pairing"
            }
            return null
        }
        return matches.singleOrNull()
    }

    /**
     * The paired device at a **typed** [host], or null when no pairing claims it or more than one
     * does (see [ai.passman.domain.connectivity.repository.TrustedDevicesRepository.getByHost]).
     *
     * Only for the manual-address path, which has no chosen device to carry. A sync session already
     * holds the record the user tapped and must hand it to [clientTls] directly — re-deriving it
     * here would reintroduce exactly the mismatch between "the device the user chose" and "the
     * device whose SPKI got pinned" that threading the record end to end removes.
     */
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
     * Client TLS for talking to [device]: presents this device's cert and pins the server to
     * [device]'s stored fingerprint. Returns null when the pairing awaits re-verification (its keys
     * are not currently trustworthy in either direction) or the session keys aren't available.
     *
     * Takes the record rather than an address on purpose. The pin is the whole point of this call,
     * and resolving "which device is at this address" is a first-match lookup over a field two
     * pairings can share — so a session could pin the SPKI of a pairing the user did not choose and
     * fail the handshake with no way to tell why.
     */
    suspend fun clientTls(device: TrustedDevice): K2kClientTls? {
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

    /**
     * Client TLS for a **typed** [host]. Resolves the address to the single pairing that claims it
     * — refusing an ambiguous one — and then pins that record. Manual-address path only; a sync
     * session calls the [TrustedDevice] overload above with the record the user chose.
     */
    suspend fun clientTls(host: String): K2kClientTls? =
        deviceForHost(host)?.let { clientTls(it) }

    private companion object {
        // In-memory only; guards the throwaway session keystore, never persisted.
        val KEYSTORE_PASSWORD = "passman-session-tls".toCharArray()

        // The k2k server scopes kind-less downloads as "download/<fileName>"; only these two names
        // (this device's classical, hybrid, and ML-DSA public keys) are fetchable by any paired device.
        val PUBLIC_KEY_DOWNLOAD_OPS = setOf("download/publicKey", "download/hybridPublicKey", "download/mldsaPublicKey")
    }
}

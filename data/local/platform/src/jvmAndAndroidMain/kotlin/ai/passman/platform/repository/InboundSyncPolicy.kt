package ai.passman.platform.repository

import ai.passman.crypto.EnvelopeCodec
import ai.passman.platform.transfer.StoredPeerKeys
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import ai.passman.repo.tls.SyncTlsProvider
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import java.security.Key

/**
 * The per-pairing-policy crypto of the receive server: which paired device an authenticated inbound
 * call belongs to, what that device's pairing permits on the wire, and how a sync-pull response is
 * sealed back to it.
 *
 * Split out of [FileTransferRepository], which keeps the server lifecycle and the handler wiring.
 * The session-scope lookup of the legacy RSA private key stays with the repository and arrives here
 * as [legacyPrivateKey].
 */
internal class InboundSyncPolicy(
    private val syncTlsProvider: SyncTlsProvider,
    private val hybridKeyManager: HybridKeyManager,
    private val mlDsaKeyManager: MlDsaKeyManager,
    private val legacyPrivateKey: suspend () -> Key,
) {

    /**
     * The paired device behind an authenticated inbound call, or a loud failure. Fails closed on a
     * null pin (plaintext or unverified — the mTLS data server always has a pin, so this is a
     * misconfiguration, not a legacy case) and on a pin no paired device matches (e.g. the device
     * was removed after its TLS handshake).
     */
    suspend fun trustedSender(pin: String?): TrustedDevice =
        syncTlsProvider.deviceForPin(pin)
            ?: error("inbound sync rejected: caller pin '${pin ?: "<none>"}' does not match a paired device")

    /**
     * Decrypt an inbound payload under [sender]'s pairing policy — exhaustive, so a new
     * [PairingSecurity] value fails compilation rather than inheriting either branch:
     *
     * - `LegacyRsa`: today's behaviour — classical v2, unsigned v3, or v4 (verified only against
     *   its own embedded key) are all accepted.
     * - `AwaitingConfirmation`: refused. The stored PQ keys exist but are not currently verified,
     *   and processing the payload as legacy instead would be a silent downgrade.
     * - `SignedHybridRequired`: only a suite-4 envelope signed by the ML-DSA key persisted at
     *   pairing. Everything else — unsigned v3, valid v4 under a different key, a substituted
     *   embedded key — throws here, before anything is staged or written.
     */
    suspend fun decryptInbound(sender: TrustedDevice, fileBytes: ByteArray): ByteArray =
        when (sender.pairingSecurity) {
            PairingSecurity.LegacyRsa -> {
                val privateKey: Key = legacyPrivateKey()
                EnvelopeCodec.decrypt(fileBytes, privateKey, hybridKeyManager.getKeyPair()?.privateKey)
            }

            PairingSecurity.AwaitingConfirmation ->
                error(StoredPeerKeys.reverificationRefusal(sender.name))

            PairingSecurity.SignedHybridRequired -> {
                val expectedSenderKey = StoredPeerKeys.mldsaVerifyKey(sender)
                    ?: error("no stored ML-DSA key for '${sender.name}'; refusing signed hybrid payload")
                val hybridPrivate = hybridKeyManager.getKeyPair()?.privateKey
                    ?: error("hybrid private key unavailable; cannot accept signed hybrid payload")
                EnvelopeCodec.decryptSignedHybrid(fileBytes, hybridPrivate, expectedSenderKey)
            }
        }

    /**
     * Seal a sync-pull response for [caller] — the outbound half of the receive server, under the
     * same exhaustive dispatch. For a `SignedHybridRequired` caller the response is encrypted to the
     * hybrid key persisted at pairing, never to [wireClientKey]: the wire key arrives with no more
     * authenticity than the transport, and honouring it would let anything that subverts the
     * transport redirect the vault to its own key. Legacy callers keep today's wire-key behaviour.
     */
    suspend fun sealSyncPullResponse(
        caller: TrustedDevice,
        plain: ByteArray,
        wireClientKey: ByteArray,
    ): ByteArray = when (caller.pairingSecurity) {
        PairingSecurity.LegacyRsa -> EnvelopeCodec.encryptHybrid(
            plain,
            EnvelopeCodec.deserializePublicKey(wireClientKey),
            mlDsaKeyManager.getKeyPair(),
        )

        PairingSecurity.AwaitingConfirmation ->
            error(StoredPeerKeys.reverificationRefusal(caller.name))

        PairingSecurity.SignedHybridRequired -> {
            val recipient = StoredPeerKeys.hybridRecipient(caller)
                ?: error("no stored hybrid key for '${caller.name}'; refusing sync pull")
            val signer = mlDsaKeyManager.getKeyPair()
                ?: error("local ML-DSA signing key unavailable; refusing sync pull")
            EnvelopeCodec.encryptHybrid(plain, recipient, signer)
        }
    }
}

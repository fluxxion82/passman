package ai.passman.platform.transfer

import ai.passman.crypto.EnvelopeCodec
import ai.passman.crypto.MlDsa
import ai.passman.repo.crypto.HybridKeyManager
import ai.passman.repo.crypto.MlDsaKeyManager
import ai.passman.repo.tls.SyncTlsProvider
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.PairingSecurity
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.settings.exception.TransferFailure
import com.k2k.test.tls.K2kClientTls
import java.net.ConnectException
import java.net.NoRouteToHostException
import java.net.SocketTimeoutException
import kotlinx.coroutines.CancellationException

/**
 * One artifact kind's wire identity.
 *
 * [kind] (the `sync-pull` path segment) and [uploadPath] are the k2k route contract and are frozen —
 * changing either silently breaks sync with every peer running an older build. [label] appears only
 * in the generic failure messages, where it has always distinguished the three artifacts; the empty
 * label of [Passwords] is why the message builders below special-case it rather than always
 * interpolating a space.
 */
data class SyncArtifact(val kind: String, val uploadPath: String?, val label: String) {
    /** "error transferring: …" for passwords, "error transferring pgp bundle: …" for the labelled kinds. */
    internal val pushFailurePrefix: String =
        if (label.isEmpty()) "error transferring" else "error transferring $label"

    internal val pullFailurePrefix: String =
        if (label.isEmpty()) "error pulling" else "error pulling $label"

    companion object {
        /** The password database. Null path: it is the artifact that rides k2k's `/upload` default. */
        val Passwords = SyncArtifact("passwords", uploadPath = null, label = "")
        val PgpKeys = SyncArtifact("pgp-keys", uploadPath = "/upload/pgp-keys", label = "pgp bundle")
        val Keystore = SyncArtifact("keystore", uploadPath = "/upload/keystore", label = "keystore bundle")
    }
}

/**
 * The seam over k2k's top-level client functions, so the per-pairing policy dispatch in
 * [ArtifactSyncClient] can be exercised without a socket. [K2k] is the only production
 * implementation and does nothing but forward.
 */
interface SyncNetwork {
    suspend fun downloadFile(name: String, host: String, port: Int, tls: K2kClientTls): ByteArray?

    /** [path] null means "k2k's default upload route" — see [K2k.uploadFile]. */
    suspend fun uploadFile(
        bytes: ByteArray,
        fileName: String,
        host: String,
        port: Int,
        path: String?,
        tls: K2kClientTls,
    )

    suspend fun requestSyncPull(
        kind: String,
        clientKey: ByteArray,
        host: String,
        port: Int,
        tls: K2kClientTls,
    ): ByteArray?

    object K2k : SyncNetwork {
        override suspend fun downloadFile(name: String, host: String, port: Int, tls: K2kClientTls): ByteArray? =
            com.k2k.test.client.downloadFile(name, host, port, tls = tls)

        /**
         * k2k's `uploadFile` declares a non-null `path: String = "/upload"`, so a null path cannot be
         * passed through: it is the *absence* of the argument, which is exactly how the password
         * artifact has always reached the default route.
         */
        override suspend fun uploadFile(
            bytes: ByteArray,
            fileName: String,
            host: String,
            port: Int,
            path: String?,
            tls: K2kClientTls,
        ) {
            if (path == null) {
                com.k2k.test.client.uploadFile(
                    file = bytes,
                    fileName = fileName,
                    ipAddress = host,
                    port = port,
                    tls = tls,
                )
            } else {
                com.k2k.test.client.uploadFile(
                    file = bytes,
                    fileName = fileName,
                    ipAddress = host,
                    port = port,
                    path = path,
                    tls = tls,
                )
            }
        }

        override suspend fun requestSyncPull(
            kind: String,
            clientKey: ByteArray,
            host: String,
            port: Int,
            tls: K2kClientTls,
        ): ByteArray? = com.k2k.test.client.requestSyncPull(kind, clientKey, host, port, tls = tls)
    }
}

/**
 * A typed address that resolves to no pairing — or to more than one, which is the same answer as far
 * as this client is concerned.
 *
 * One message for both because it reaches the manual-transfer screen verbatim, and "host not paired"
 * would be a lie in the second case: the peer *is* paired, twice over, and picking one of the two
 * would pin an arbitrary SPKI (see `TrustedDevicesRepository.getByHost` for how one address ends up
 * with two claimants). The way out of either case is the same — pair the peer, or start the sync
 * from the chooser, which carries the record itself and never has to resolve an address at all.
 */
private fun unresolvedHostMessage(host: String): String =
    "no single paired device at $host - pair it, or pick the device from the sync chooser"

/**
 * Push/pull of one sync artifact, dispatched on the target device's [PairingSecurity]:
 *
 * - `LegacyRsa` keeps today's behaviour exactly — peer keys are fetched over the mTLS channel each
 *   sync and signing is opportunistic.
 * - `SignedHybridRequired` uses only the keys persisted at pairing confirmation: it encrypts to the
 *   stored hybrid key, always signs with the local ML-DSA key, and never fetches key material over
 *   the wire. Pulled payloads must be suite-4 envelopes signed by the stored peer ML-DSA key.
 * - `AwaitingConfirmation` is refused outright, before any network I/O — the stored PQ keys are not
 *   currently verified, and falling back to legacy would be the silent downgrade the state forbids.
 *
 * Every dispatch is an exhaustive `when` so a new [PairingSecurity] value fails compilation.
 *
 * This policy used to be copy-pasted into `JvmPasswordTransferService`, `JvmPgpTransferService` and
 * `JvmKeystoreTransferService`, which differed only in the [SyncArtifact] they carried; those three
 * are now thin delegates so the dispatch is maintained once.
 */
class ArtifactSyncClient(
    private val syncTlsProvider: SyncTlsProvider,
    private val hybridKeyManager: HybridKeyManager,
    private val mlDsaKeyManager: MlDsaKeyManager,
    private val network: SyncNetwork = SyncNetwork.K2k,
) {
    /**
     * Push to a **typed** address: resolves it to the single pairing that claims it (an ambiguous
     * address resolves to nothing — see
     * [ai.passman.domain.connectivity.repository.TrustedDevicesRepository.getByHost]) and then runs
     * the device-taking overload below. Only the manual-address path should reach this; a sync
     * session already holds the record the user chose and must pass it.
     */
    suspend fun push(
        artifact: SyncArtifact,
        plaintext: ByteArray,
        fileName: String,
        hostName: String,
        port: Int,
    ): Outcome<Unit> {
        val device = syncTlsProvider.deviceForHost(hostName)
            ?: return Outcome.Error(unresolvedHostMessage(hostName), TransferFailure.GeneralTransferFailure)
        return push(artifact, plaintext, fileName, device, port)
    }

    /**
     * Push to [device] — the record the user chose, carried the whole way rather than re-derived
     * from an address. Everything below pins [device]'s own SPKI and reads [device]'s own stored
     * peer keys, so the pairing that gets pinned is always the pairing that was picked, even when a
     * second record shares its [TrustedDevice.lastHost].
     */
    suspend fun push(
        artifact: SyncArtifact,
        plaintext: ByteArray,
        fileName: String,
        device: TrustedDevice,
        port: Int,
    ): Outcome<Unit> = runCatching {
        val hostName = device.lastHost
        when (device.pairingSecurity) {
            PairingSecurity.AwaitingConfirmation -> Outcome.Error(
                StoredPeerKeys.reverificationRefusal(device.name),
                TransferFailure.GeneralTransferFailure,
            )

            PairingSecurity.LegacyRsa -> {
                val tls = syncTlsProvider.clientTls(device)
                    ?: return Outcome.Error("host not paired: $hostName", TransferFailure.GeneralTransferFailure)
                val peerHybridKey = network.downloadFile("hybridPublicKey", hostName, port, tls = tls)
                    ?: return Outcome.Error("public key is null", TransferFailure.PublicKeyFetchFailure)
                val peerMlDsaKey = runCatching {
                    network.downloadFile("mldsaPublicKey", hostName, port, tls = tls)
                }.getOrElse {
                    if (it is CancellationException) throw it
                    null
                }

                val recipient = EnvelopeCodec.deserializePublicKey(peerHybridKey)
                val signer = mlDsaKeyManager.getKeyPair()?.takeIf { peerMlDsaKey?.size == MlDsa.PUBLIC_KEY_BYTES }
                val encrypted = EnvelopeCodec.encryptHybrid(plaintext, recipient, signer)

                network.uploadFile(
                    bytes = encrypted,
                    fileName = fileName,
                    host = hostName,
                    port = port,
                    path = artifact.uploadPath,
                    tls = tls,
                )
                Outcome.Success(Unit)
            }

            PairingSecurity.SignedHybridRequired -> {
                val recipient = StoredPeerKeys.hybridRecipient(device)
                    ?: return Outcome.Error(
                        "no stored hybrid key for '${device.name}'",
                        TransferFailure.GeneralTransferFailure,
                    )
                val signer = mlDsaKeyManager.getKeyPair()
                    ?: return Outcome.Error(
                        "local ML-DSA signing key unavailable",
                        TransferFailure.GeneralTransferFailure,
                    )
                val tls = syncTlsProvider.clientTls(device)
                    ?: return Outcome.Error("host not paired: $hostName", TransferFailure.GeneralTransferFailure)

                network.uploadFile(
                    bytes = EnvelopeCodec.encryptHybrid(plaintext, recipient, signer),
                    fileName = fileName,
                    host = hostName,
                    port = port,
                    path = artifact.uploadPath,
                    tls = tls,
                )
                Outcome.Success(Unit)
            }
        }
    }.getOrElse {
        if (it is CancellationException) throw it
        when (it) {
            // NoRouteToHostException is ConnectException's sibling under SocketException - the
            // classic dozing-Wi-Fi-peer error, and without it here a phone that let its radio sleep
            // failed the *first* push attempt with no retry, since this mapping is what decides
            // whether runSyncSession's retry loop ever sees PeerUnreachable at all.
            //
            // SocketException("Connection reset") and EOFException are deliberately left out and
            // therefore terminal: they can mean a transfer was cut *part-way through*, which is not
            // the same claim as "nobody answered" - retrying that blind could re-drive a push into a
            // peer that is mid-processing the last one. Revisit with evidence, not by guessing.
            is ConnectException, is SocketTimeoutException, is NoRouteToHostException ->
                Outcome.Error("peer unreachable: ${it.message}", TransferFailure.PeerUnreachable(device.lastHost))
            else ->
                Outcome.Error("${artifact.pushFailurePrefix}: ${it.message}", TransferFailure.GeneralTransferFailure)
        }
    }

    /** Pull from a **typed** address. Mirrors [push]'s host overload — resolve, then delegate. */
    suspend fun pull(
        artifact: SyncArtifact,
        hostName: String,
        port: Int,
    ): Outcome<ByteArray> {
        val device = syncTlsProvider.deviceForHost(hostName)
            ?: return Outcome.Error(unresolvedHostMessage(hostName), TransferFailure.GeneralTransferFailure)
        return pull(artifact, device, port)
    }

    /** Pull from [device], the record the user chose. See [push]'s device overload. */
    suspend fun pull(
        artifact: SyncArtifact,
        device: TrustedDevice,
        port: Int,
    ): Outcome<ByteArray> = runCatching {
        val hostName = device.lastHost
        when (device.pairingSecurity) {
            PairingSecurity.AwaitingConfirmation -> Outcome.Error(
                StoredPeerKeys.reverificationRefusal(device.name),
                TransferFailure.GeneralTransferFailure,
            )

            PairingSecurity.LegacyRsa -> {
                val tls = syncTlsProvider.clientTls(device)
                    ?: return Outcome.Error("host not paired: $hostName", TransferFailure.GeneralTransferFailure)
                val keyPair = hybridKeyManager.getKeyPair()
                    ?: return Outcome.Error("no hybrid key", TransferFailure.GeneralTransferFailure)
                val peerMlDsaKey = runCatching {
                    network.downloadFile("mldsaPublicKey", hostName, port, tls = tls)
                }.getOrElse {
                    if (it is CancellationException) throw it
                    null
                }
                    ?.takeIf { it.size == MlDsa.PUBLIC_KEY_BYTES }
                val response = network.requestSyncPull(
                    artifact.kind, EnvelopeCodec.serializePublicKey(keyPair.publicKey), hostName, port, tls = tls,
                )
                val plaintext = if (response == null || response.isEmpty()) ByteArray(0)
                else EnvelopeCodec.decrypt(response, keyPair.privateKey, peerMlDsaKey)
                Outcome.Success(plaintext)
            }

            PairingSecurity.SignedHybridRequired -> {
                val expectedSenderKey = StoredPeerKeys.mldsaVerifyKey(device)
                    ?: return Outcome.Error(
                        "no stored ML-DSA key for '${device.name}'",
                        TransferFailure.GeneralTransferFailure,
                    )
                val tls = syncTlsProvider.clientTls(device)
                    ?: return Outcome.Error("host not paired: $hostName", TransferFailure.GeneralTransferFailure)
                val keyPair = hybridKeyManager.getKeyPair()
                    ?: return Outcome.Error("no hybrid key", TransferFailure.GeneralTransferFailure)
                val response = network.requestSyncPull(
                    artifact.kind, EnvelopeCodec.serializePublicKey(keyPair.publicKey), hostName, port, tls = tls,
                )
                val plaintext = if (response == null || response.isEmpty()) ByteArray(0)
                else EnvelopeCodec.decryptSignedHybrid(response, keyPair.privateKey, expectedSenderKey)
                Outcome.Success(plaintext)
            }
        }
    }.getOrElse {
        if (it is CancellationException) throw it
        when (it) {
            // Mirrors push's mapping above - see its comment for why NoRouteToHostException joins
            // the retryable pair and why a reset/EOF stays terminal. This is also the mapping that
            // now feeds runSyncSession's pull-retry loop: a PeerUnreachable here is what makes a
            // retried pull retry, and anything else here is what keeps a retried pull terminal.
            is ConnectException, is SocketTimeoutException, is NoRouteToHostException ->
                Outcome.Error("peer unreachable: ${it.message}", TransferFailure.PeerUnreachable(device.lastHost))
            else ->
                Outcome.Error("${artifact.pullFailurePrefix}: ${it.message}", TransferFailure.GeneralTransferFailure)
        }
    }
}

package ai.passman.domain.settings.exception

import ai.passman.domain.exception.Failure

sealed class TransferFailure {
    data object PublicKeyFetchFailure: Failure.FeatureFailure()
    data object GeneralTransferFailure: Failure.FeatureFailure()
    data class PeerUnreachable(val host: String): Failure.FeatureFailure()
    data object NoSavedAddress: Failure.FeatureFailure()
    data class FingerprintMismatch(
        val host: String,
        val deviceName: String,
        val expected: String,
        val actual: String,
    ): Failure.FeatureFailure()
    data class PeerSyncTimeout(val host: String): Failure.FeatureFailure()
    data object SyncCancelled: Failure.FeatureFailure()
}

package ai.passman.domain.settings.model

sealed class TransferEvent {
    data class PassFileReceived(val conflict: Boolean) : TransferEvent()
    data object PgpKeysReceived : TransferEvent()
    data object KeystoreReceived : TransferEvent()
}

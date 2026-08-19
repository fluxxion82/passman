package ai.passman.domain.keystore.model

sealed class KeystoreEvent {
    object Created : KeystoreEvent()
    object Updated : KeystoreEvent()
    data class DeletedKeystore(val path: String) : KeystoreEvent()
    data class DeletedKeystoreKey(val path: String, val keyAlias: String) : KeystoreEvent()
}

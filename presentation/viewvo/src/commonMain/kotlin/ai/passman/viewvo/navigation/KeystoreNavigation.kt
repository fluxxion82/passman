package ai.passman.viewvo.navigation

sealed interface KeystoreNavigation
sealed interface KeystoreDetailsNavigation
sealed interface CreateKeyStoreNavigation
sealed interface AddKeyStorKeyNavigation

data class KeystoreDetails(val keystorePath: String, val keystoreName: String) : KeystoreNavigation

data class KeystoreTools(val keystorePath: String, val keystoreName: String, val keyAlias: String): KeystoreDetailsNavigation
data class AddKeystoreKey(val keystorePath: String, val keystoreName: String) :KeystoreDetailsNavigation
data object UpdateKeystoreError: KeystoreDetailsNavigation

data object SuccessCreation : CreateKeyStoreNavigation, AddKeyStorKeyNavigation
data class ErrorCreation(val message: String) : CreateKeyStoreNavigation, AddKeyStorKeyNavigation

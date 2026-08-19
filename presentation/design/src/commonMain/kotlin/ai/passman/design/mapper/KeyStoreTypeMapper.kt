package ai.passman.design.mapper

import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import androidx.compose.runtime.Composable

@Composable
fun KeyStoreType.toDisplayName(): String {
    return when (this) {
        KeyStoreType.ANDROID -> "Android Keystore"
        KeyStoreType.PKCS12 -> "PKCS12"
        KeyStoreType.BKS -> "BKS"
        KeyStoreType.JKS -> "JKS"
    }
}

@Composable
fun KeyStoreType.toAllowedKeyAlgos(): List<KeystoreKeyAlgorithm> {
    return when (this) {
        KeyStoreType.ANDROID -> listOf()
        KeyStoreType.PKCS12 -> listOf(KeystoreKeyAlgorithm.RSA)
        KeyStoreType.BKS -> listOf(KeystoreKeyAlgorithm.RSA)
        KeyStoreType.JKS -> listOf(KeystoreKeyAlgorithm.RSA)
    }
}

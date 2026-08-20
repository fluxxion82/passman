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
        // PKCS#12 and BKS both hold secret keys, so an AES entry is a real option there. JKS does
        // not — it stores private keys and certificates only, and offering AES would produce a
        // KeyStoreException at the point of saving.
        KeyStoreType.PKCS12 -> listOf(KeystoreKeyAlgorithm.RSA, KeystoreKeyAlgorithm.AES)
        KeyStoreType.BKS -> listOf(KeystoreKeyAlgorithm.RSA, KeystoreKeyAlgorithm.AES)
        KeyStoreType.JKS -> listOf(KeystoreKeyAlgorithm.RSA)
    }
}

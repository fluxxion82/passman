package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.crypto.repository.CryptoPreferences
import ai.passman.domain.keystore.repository.KeystoreRepository

class ClearCryptoKeys(
    private val keystoreRepository: KeystoreRepository,
    private val cryptoPreferences: CryptoPreferences
) : Usecase<Unit, Unit> {

    override suspend fun invoke(param: Unit) {
        cryptoPreferences.clearEncryptedData()
        keystoreRepository.clearKeyStore()
    }
}

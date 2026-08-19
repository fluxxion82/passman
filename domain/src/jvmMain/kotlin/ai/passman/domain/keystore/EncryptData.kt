package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.EncryptedData
import ai.passman.domain.keystore.service.CipherService
import javax.crypto.Cipher

class EncryptData(
    private val cryptoService: CipherService
) : Usecase<EncryptData.Data, Outcome<EncryptedData>> {

    data class Data(val plaintext: ByteArray, val cipher: Cipher)

    override suspend fun invoke(param: Data): Outcome<EncryptedData> =
        cryptoService.encryptData(param.plaintext, param.cipher)
}

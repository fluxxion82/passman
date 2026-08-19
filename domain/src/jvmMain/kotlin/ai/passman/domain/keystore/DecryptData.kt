package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.service.CipherService
import javax.crypto.Cipher

class DecryptData(
    private val authService: CipherService
) : Usecase<DecryptData.Data, Outcome<ByteArray>> {

    data class Data(val cipherText: ByteArray, val cipher: Cipher)

    override suspend fun invoke(param: Data): Outcome<ByteArray> =
        authService.decryptData(param.cipherText, param.cipher)
}

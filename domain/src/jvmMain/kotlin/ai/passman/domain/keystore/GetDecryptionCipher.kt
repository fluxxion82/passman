package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.DecryptInfo
import ai.passman.domain.keystore.service.CipherService
import javax.crypto.Cipher

class GetDecryptionCipher(
    private val authService: CipherService
) : Usecase<DecryptInfo, Outcome<Cipher>> {

    override suspend fun invoke(param: DecryptInfo): Outcome<Cipher> =
        authService.getInitializedCipherForDecryption(param)
}

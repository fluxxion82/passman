package ai.passman.domain.keystore

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.crypto.model.EncryptInfo
import ai.passman.domain.keystore.service.CipherService
import javax.crypto.Cipher

class GetEncryptionCipher(
    private val keystoreService: CipherService
) : Usecase<EncryptInfo, Outcome<Cipher>> {

    override suspend fun invoke(param: EncryptInfo): Outcome<Cipher> =
        keystoreService.getInitializedCipherForEncryption(param)
}

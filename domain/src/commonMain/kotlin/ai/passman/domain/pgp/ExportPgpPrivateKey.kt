package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

/**
 * Guarded private-key export: resolves the secret-ring file for a key, but only after the
 * repository has verified the passphrase by actually unlocking the secret key. The returned path
 * is the passphrase-encrypted ring file as it sits on disk — key material is never decrypted for
 * export.
 */
class ExportPgpPrivateKey(
    private val pgpRepository: PgpRepository,
) : Usecase<ExportPgpPrivateKey.Request, Outcome<String>> {
    data class Request(val keyId: Long, val passphrase: String) {
        /** Keeps the passphrase out of logs and error messages. */
        override fun toString(): String = "Request(keyId=$keyId, passphrase=***)"
    }

    override suspend fun invoke(param: Request): Outcome<String> {
        return pgpRepository.getSecretKeyPath(keyId = param.keyId, passphrase = param.passphrase)
    }
}

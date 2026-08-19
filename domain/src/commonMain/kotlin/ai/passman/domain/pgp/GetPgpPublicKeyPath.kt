package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.repository.PgpRepository

/** Resolves the only key-file path that is safe to share: see [PgpRepository.getPublicKeyPath]. */
class GetPgpPublicKeyPath(
    private val pgpRepository: PgpRepository,
) : Usecase<Long, Outcome<String>> {
    override suspend fun invoke(param: Long): Outcome<String> {
        return pgpRepository.getPublicKeyPath(keyId = param)
    }
}

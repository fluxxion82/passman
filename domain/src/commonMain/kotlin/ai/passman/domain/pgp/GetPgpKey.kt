package ai.passman.domain.pgp

import ai.passman.domain.base.Usecase
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.repository.PgpRepository

class GetPgpKey(
    private val pgpRepository: PgpRepository,
): Usecase<Long, PgpKeyPair?> {
    override suspend fun invoke(param: Long): PgpKeyPair? {
        return pgpRepository.getKey(keyId = param)
    }
}

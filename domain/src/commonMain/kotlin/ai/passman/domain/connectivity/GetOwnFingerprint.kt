package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.service.FingerprintService

class GetOwnFingerprint(
    private val fingerprintService: FingerprintService,
): Usecase<Unit, Outcome<String>> {
    override suspend fun invoke(param: Unit): Outcome<String> = fingerprintService.getOwnFingerprint()
}

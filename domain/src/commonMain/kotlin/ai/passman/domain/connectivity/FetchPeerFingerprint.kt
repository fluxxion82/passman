package ai.passman.domain.connectivity

import ai.passman.domain.base.Usecase
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.service.FingerprintService

class FetchPeerFingerprint(
    private val fingerprintService: FingerprintService,
): Usecase<String, Outcome<String>> {
    override suspend fun invoke(param: String): Outcome<String> = fingerprintService.fetchPeerFingerprint(param)
}

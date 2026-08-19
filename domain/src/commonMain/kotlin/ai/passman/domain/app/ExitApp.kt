package ai.passman.domain.app

import ai.passman.domain.base.Usecase

class ExitApp : Usecase<Unit, Unit> {
    override suspend fun invoke(param: Unit) = Unit
}

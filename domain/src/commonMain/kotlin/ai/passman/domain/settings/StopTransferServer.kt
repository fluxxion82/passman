package ai.passman.domain.settings

import ai.passman.domain.base.Usecase
import ai.passman.domain.settings.repository.TransferRepository

/**
 * Releases the lease [StartTransferServer] took out. Added alongside the shared server's
 * refcounting (see `TransferRepository.startTransferServer`'s KDoc): anything that takes a lease
 * needs a matching release, and until this existed [TransferViewModel] was the one caller with no
 * way to give its lease back - see its KDoc for what that call site does with it.
 */
class StopTransferServer(
    val service: TransferRepository,
): Usecase<Unit, Unit> {
    override suspend fun invoke(param: Unit) {
        service.stopTransferServer()
    }
}

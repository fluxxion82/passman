package ai.passman.domain.password

import ai.passman.domain.base.Usecase
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.repository.PasswordRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.channelFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onStart

class GetPasswordEntries(
    private val passwordRepository: PasswordRepository,
    private val passwordEventPersistence: PasswordEventPersistence,
) : Usecase<Unit, Flow<List<PasswordEntry>>> {

    override suspend fun invoke(param: Unit): Flow<List<PasswordEntry>> = channelFlow {
        val passwordEvents = passwordEventPersistence.events()

        passwordEvents
            .onStart {
                send(passwordRepository.getPasswordEntries().sortedBy { it.entryName.lowercase() })
            }
            .map { passwordRepository.getPasswordEntries() }
            .collect { entryList ->
                send(entryList.sortedBy { it.entryName.lowercase() })
        }
    }
}

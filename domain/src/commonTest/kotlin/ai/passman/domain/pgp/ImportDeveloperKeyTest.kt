package ai.passman.domain.pgp

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.persistence.PgpEventPersistence
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.runTest

class ImportDeveloperKeyTest {

    private class RecordingPgpEvents : PgpEventPersistence {
        val updates = mutableListOf<PgpEvent>()
        override fun events(): Flow<PgpEvent> = emptyFlow()
        override suspend fun update(event: PgpEvent) {
            updates += event
        }
    }

    @Test
    fun aRealImportEmitsTheKeyCreatedRefreshEvent() = runTest {
        val repository = FakePgpRepository(importDeveloperKey = { Outcome.Success(true) })
        val events = RecordingPgpEvents()

        val outcome = ImportDeveloperKey(repository, events)(ImportDeveloperKey.Mode.OncePerAccount)

        assertEquals(true, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertEquals(listOf<PgpEvent>(PgpEvent.KeyCreated), events.updates)
        assertEquals(listOf(false), repository.importDeveloperKeyCalls, "OncePerAccount must not force")
    }

    @Test
    fun theAlreadyImportedSkipEmitsNoEvent() = runTest {
        // Nothing changed on disk, so an event would trigger a pointless key list reload.
        val repository = FakePgpRepository(importDeveloperKey = { Outcome.Success(false) })
        val events = RecordingPgpEvents()

        val outcome = ImportDeveloperKey(repository, events)(ImportDeveloperKey.Mode.OncePerAccount)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertTrue(events.updates.isEmpty())
    }

    @Test
    fun aFailedImportEmitsNoEventAndSurfacesTheError() = runTest {
        val repository = FakePgpRepository(
            importDeveloperKey = { Outcome.Error("refused", PgpFailure.ImportKeyFailure) },
        )
        val events = RecordingPgpEvents()

        val outcome = ImportDeveloperKey(repository, events)(ImportDeveloperKey.Mode.Force)

        assertEquals(PgpFailure.ImportKeyFailure, assertIs<Outcome.Error>(outcome).cause)
        assertTrue(events.updates.isEmpty())
        assertEquals(listOf(true), repository.importDeveloperKeyCalls, "Force must pass force=true")
    }
}

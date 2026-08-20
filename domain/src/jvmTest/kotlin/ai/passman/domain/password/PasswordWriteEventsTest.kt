package ai.passman.domain.password

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.repository.PasswordRepository
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.test.runTest

/**
 * A `PasswordEvent` is the UI's only signal that a write landed: `Created` navigates the add screen
 * away, `Updated`/`Deleted` refresh the list. Emitting one after a publish that *failed* tells the
 * user their credential was saved when it was not — the repository retries three times and can
 * exhaust them, and before this change the use cases discarded that answer and reported success
 * unconditionally. So the contract under test is: **the event fires iff the repository says the
 * write was published, and the caller gets the same answer.**
 */
class PasswordWriteEventsTest {

    private val events = RecordingEvents()

    // ------------------------------------------------------------------ add

    @Test
    fun `a published add emits Created and reports true`() = runTest {
        val outcome = AddPassword(StubRepository(writeResult = true), events).invoke(entryData("vault-door"))

        assertTrue(outcome)
        assertEquals(listOf<PasswordEvent>(PasswordEvent.Created), events.recorded)
    }

    @Test
    fun `an add that could not publish emits nothing and reports false`() = runTest {
        val outcome = AddPassword(StubRepository(writeResult = false), events).invoke(entryData("vault-door"))

        assertFalse(outcome, "three exhausted retries must not be reported as a save")
        assertEquals(emptyList(), events.recorded, "no event may claim a write that never landed")
    }

    // ------------------------------------------------------------------ update

    @Test
    fun `a published update emits Updated and reports true`() = runTest {
        val outcome = UpdatePassword(StubRepository(writeResult = true), events).invoke(entry("cellar"))

        assertTrue(outcome)
        assertEquals(listOf<PasswordEvent>(PasswordEvent.Updated), events.recorded)
    }

    @Test
    fun `an update that could not publish emits nothing and reports false`() = runTest {
        val outcome = UpdatePassword(StubRepository(writeResult = false), events).invoke(entry("cellar"))

        assertFalse(outcome)
        assertEquals(emptyList(), events.recorded)
    }

    // ------------------------------------------------------------------ delete

    @Test
    fun `a published delete emits Deleted with the uuid and reports true`() = runTest {
        val outcome = DeletePassword(StubRepository(writeResult = true), events).invoke("uuid-lantern")

        assertTrue(outcome)
        assertEquals(listOf<PasswordEvent>(PasswordEvent.Deleted("uuid-lantern")), events.recorded)
    }

    @Test
    fun `a delete that removed nothing emits nothing and reports false`() = runTest {
        val outcome = DeletePassword(StubRepository(writeResult = false), events).invoke("uuid-lantern")

        assertFalse(outcome, "an absent target or a lost publish is not a delete")
        assertEquals(emptyList(), events.recorded)
    }

    // ------------------------------------------------------------------ batch delete

    @Test
    fun `a batch delete that removed rows emits one Updated and reports the count`() = runTest {
        val removed = DeletePasswords(StubRepository(batchResult = 2), events).invoke(setOf("a", "b", "c"))

        assertEquals(2, removed)
        assertEquals(listOf<PasswordEvent>(PasswordEvent.Updated), events.recorded)
    }

    @Test
    fun `a batch delete that removed nothing emits nothing`() = runTest {
        val removed = DeletePasswords(StubRepository(batchResult = 0), events).invoke(setOf("a", "b"))

        assertEquals(0, removed)
        assertEquals(emptyList(), events.recorded, "an unchanged vault is not an update")
    }

    // ------------------------------------------------------------------ fixtures

    private fun entryData(name: String) = AddPassword.EntryData(
        entryName = name,
        userName = "carol",
        password = "pw-$name",
        website = "https://$name.example",
        notes = "",
    )

    private fun entry(name: String) = PasswordEntry(
        uuid = "uuid-$name",
        id = "4",
        entryName = name,
        username = "carol",
        password = "pw-$name",
        website = "https://$name.example",
        notes = "",
        dateCreated = 77L,
    )

    private class RecordingEvents : PasswordEventPersistence {
        val recorded = mutableListOf<PasswordEvent>()
        override fun events(): Flow<PasswordEvent> = emptyFlow()
        override suspend fun update(event: PasswordEvent) {
            recorded += event
        }
    }

    /** Answers every mutation with the configured result; the read-side methods are unreachable here. */
    private class StubRepository(
        private val writeResult: Boolean = true,
        private val batchResult: Int = 0,
    ) : PasswordRepository {
        override suspend fun addPasswordEntry(entry: AddPassword.EntryData): Boolean = writeResult
        override suspend fun updatePasswordEntry(entry: PasswordEntry): Boolean = writeResult
        override suspend fun deletePasswordEntry(passwordUuid: String): Boolean = writeResult
        override suspend fun deletePasswordEntries(passwordUuids: Collection<String>): Int = batchResult
        override suspend fun getPasswordEntries(): List<PasswordEntry> = error("not a read test")
        override suspend fun transferPasswordDatabase(hostName: String): Outcome<Unit> = error("not a transfer test")
        override suspend fun pushPasswordDatabase(device: TrustedDevice): Outcome<Unit> = error("not a transfer test")
        override suspend fun pullPasswordDatabase(device: TrustedDevice): Outcome<Unit> = error("not a transfer test")
    }
}

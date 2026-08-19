package ai.passman.domain.settings

import ai.passman.domain.base.invoke
import ai.passman.domain.settings.model.SyncLogEntry
import ai.passman.domain.settings.repository.SyncLogRepository
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class GetSyncLogTest {
    private val repository: SyncLogRepository = mockk(relaxed = true)
    private val getSyncLog = GetSyncLog(repository)

    @Test
    fun `returns the repository's recent entries unchanged`() = runTest {
        val entries = listOf(
            SyncLogEntry(at = 2L, artifact = "passwords", host = "h", outcome = SyncLogEntry.OUTCOME_SUCCESS),
            SyncLogEntry(at = 1L, artifact = "pgp-keys", host = "h", outcome = SyncLogEntry.OUTCOME_FAILED),
        )
        coEvery { repository.recent() } returns entries

        assertEquals(entries, getSyncLog())
    }
}

class ClearSyncLogTest {
    private val repository: SyncLogRepository = mockk(relaxed = true)
    private val clearSyncLog = ClearSyncLog(repository)

    @Test
    fun `forwards the clear to the repository`() = runTest {
        clearSyncLog()
        coVerify(exactly = 1) { repository.clear() }
    }
}

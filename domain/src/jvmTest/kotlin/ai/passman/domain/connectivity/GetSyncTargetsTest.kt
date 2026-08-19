package ai.passman.domain.connectivity

import ai.passman.domain.base.invoke
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import io.mockk.coEvery
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlinx.coroutines.test.runTest

class GetSyncTargetsTest {
    private val repository: TrustedDevicesRepository = mockk(relaxed = true)
    private val getSyncTargets = GetSyncTargets(repository)

    private fun device(name: String, lastSyncedAt: Long) = TrustedDevice(
        name = name,
        fingerprint = "fp-$name",
        lastHost = "10.0.0.1",
        lastSyncedAt = lastSyncedAt,
    )

    @Test
    fun `empty store yields empty targets`() = runTest {
        coEvery { repository.getAll() } returns emptyList()
        assertEquals(emptyList(), getSyncTargets())
    }

    @Test
    fun `targets are sorted most recently synced first`() = runTest {
        coEvery { repository.getAll() } returns listOf(
            device("old", lastSyncedAt = 100),
            device("new", lastSyncedAt = 300),
            device("mid", lastSyncedAt = 200),
        )
        assertEquals(listOf("new", "mid", "old"), getSyncTargets().map { it.name })
    }

    @Test
    fun `never-synced devices sort last, by name`() = runTest {
        coEvery { repository.getAll() } returns listOf(
            device("zeta", lastSyncedAt = 0),
            device("alpha", lastSyncedAt = 0),
            device("synced", lastSyncedAt = 50),
        )
        assertEquals(listOf("synced", "alpha", "zeta"), getSyncTargets().map { it.name })
    }

    @Test
    fun `the name tie-break ignores case`() = runTest {
        coEvery { repository.getAll() } returns listOf(
            device("Zeta", lastSyncedAt = 0),
            device("alpha", lastSyncedAt = 0),
        )
        assertEquals(listOf("alpha", "Zeta"), getSyncTargets().map { it.name })
    }
}

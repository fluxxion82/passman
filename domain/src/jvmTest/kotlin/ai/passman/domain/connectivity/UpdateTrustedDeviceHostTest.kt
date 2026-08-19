package ai.passman.domain.connectivity

import ai.passman.domain.connectivity.repository.TrustedDevicesRepository
import io.mockk.coVerify
import io.mockk.mockk
import kotlin.test.Test
import kotlinx.coroutines.test.runTest

class UpdateTrustedDeviceHostTest {
    private val repository: TrustedDevicesRepository = mockk(relaxed = true)
    private val updateTrustedDeviceHost = UpdateTrustedDeviceHost(repository)

    @Test
    fun `forwards name and host to the repository`() = runTest {
        updateTrustedDeviceHost(UpdateTrustedDeviceHost.Parameters(name = "desk", host = "10.0.0.9"))
        coVerify(exactly = 1) { repository.updateHost("desk", "10.0.0.9") }
    }

    @Test
    fun `trims surrounding whitespace off the host before persisting`() = runTest {
        updateTrustedDeviceHost(UpdateTrustedDeviceHost.Parameters(name = "desk", host = "  10.0.0.9 "))
        coVerify(exactly = 1) { repository.updateHost("desk", "10.0.0.9") }
    }

    @Test
    fun `a blank host never reaches the repository`() = runTest {
        updateTrustedDeviceHost(UpdateTrustedDeviceHost.Parameters(name = "desk", host = "   "))
        coVerify(exactly = 0) { repository.updateHost(any(), any()) }
    }
}

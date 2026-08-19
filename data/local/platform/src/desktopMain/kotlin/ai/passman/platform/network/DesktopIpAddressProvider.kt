package ai.passman.platform.network

import ai.passman.domain.base.CoroutinesContextFacade
import com.k2k.NetInterface
import kotlinx.coroutines.withContext

class DesktopIpAddressProvider(
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : IpAddressProvider {
    override suspend fun getLocalIpAddress(): String = withContext(coroutinesContextFacade.io) {
        NetInterface.getLocalAddress()
    }
}

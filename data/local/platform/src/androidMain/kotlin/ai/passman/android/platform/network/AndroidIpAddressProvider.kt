package ai.passman.android.platform.network

import ai.passman.platform.network.IpAddressProvider
import ai.passman.domain.base.CoroutinesContextFacade
import android.content.Context
import android.net.wifi.WifiManager
import java.net.InetAddress
import kotlinx.coroutines.withContext

class AndroidIpAddressProvider(
    private val context: Context,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : IpAddressProvider {
    override suspend fun getLocalIpAddress(): String = withContext(coroutinesContextFacade.io) {
        val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val wifiInfo = wifiManager.connectionInfo
        val ipAddress = wifiInfo.ipAddress
        InetAddress.getByAddress(
            byteArrayOf(
                (ipAddress and 0xFF).toByte(),
                (ipAddress shr 8 and 0xFF).toByte(),
                (ipAddress shr 16 and 0xFF).toByte(),
                (ipAddress shr 24 and 0xFF).toByte(),
            ),
        ).hostAddress ?: "error"
    }
}

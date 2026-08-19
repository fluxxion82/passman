package ai.passman.platform.network

interface IpAddressProvider {
    suspend fun getLocalIpAddress(): String
}

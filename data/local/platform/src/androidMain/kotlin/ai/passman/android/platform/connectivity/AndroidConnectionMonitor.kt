package ai.passman.android.platform.connectivity

import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.connectivity.model.ConnectionState
import ai.passman.domain.connectivity.persistence.ConnectionMonitor
import android.content.Context
import android.net.*
import android.os.Build
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.onCompletion
import kotlinx.coroutines.flow.onStart
import kotlinx.coroutines.launch

internal class AndroidConnectionMonitor(
    context: Context,
    private val contextFacade: CoroutineScopeFacade
) : ConnectionMonitor {

    private val connectivityManager by lazy {
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    }

    private val connectionState = MutableSharedFlow<ConnectionState>(1)

    override suspend fun getConnectionState(): Flow<ConnectionState> {
        updateConnectionState(isConnected())

        return connectionState
            .onStart { registerCallback() }
            .onCompletion { unregisterCallback() }
    }

    private suspend fun updateConnectionState(state: ConnectionState) {
        connectionState.emit(state)
    }

    private fun isConnected(): ConnectionState {
        val activeNetwork: NetworkInfo? = connectivityManager.activeNetworkInfo

        return if (activeNetwork?.isConnected == true) {
            ConnectionState.CONNECTED
        } else {
            ConnectionState.DISCONNECTED
        }
    }

    private fun registerCallback() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            connectivityManager.registerDefaultNetworkCallback(networkCallback)
        } else {
            val networkRequestBuilder =
                NetworkRequest.Builder()
                    .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                    .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)

            connectivityManager.registerNetworkCallback(networkRequestBuilder.build(), networkCallback)
        }
    }

    private fun unregisterCallback() {
        connectivityManager.unregisterNetworkCallback(networkCallback)
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            super.onAvailable(network)
            contextFacade.globalScope.launch {
                updateConnectionState(ConnectionState.CONNECTED)
            }
        }

        override fun onLost(network: Network) {
            super.onLost(network)
            contextFacade.globalScope.launch {
                updateConnectionState(ConnectionState.DISCONNECTED)
            }
        }
    }
}

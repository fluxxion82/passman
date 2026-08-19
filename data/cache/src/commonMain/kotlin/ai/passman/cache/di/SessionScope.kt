package ai.passman.cache.di

import org.koin.core.qualifier.named
import org.koin.core.scope.Scope
import org.koin.mp.KoinPlatform

suspend fun <R> passmanSessionScope(sessionId: String, block: suspend (Scope)-> R): R {
    return getSessionScope(sessionId, "sessionScope", block)
}

suspend fun <R> keystoreCacheScope(sessionId: String, block: suspend (Scope)-> R): R {
    return getSessionScope(sessionId, "keystoreCacheScope", block)
}

fun closeKeystoreCacheScope(sessionId: String) {
    if (sessionId.isNotEmpty()) {
        KoinPlatform.getKoin().getScopeOrNull("session-$sessionId")?.close()
    }
}

suspend fun <R> getSessionScope(sessionId: String, sessionName: String, block: suspend (Scope)-> R): R {
    return block(
        KoinPlatform.getKoin().getOrCreateScope("session-$sessionId", named(sessionName))
    )
}

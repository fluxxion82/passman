package ai.passman.domain.base

import kotlin.coroutines.CoroutineContext

interface CoroutinesContextFacade {
    val io: CoroutineContext
    val main: CoroutineContext
    val default: CoroutineContext
    val unconfined: CoroutineContext
    val errorHandler: CoroutineContext
}

expect class DefaultContextFacade

expect fun defaultContextFacade(): CoroutinesContextFacade

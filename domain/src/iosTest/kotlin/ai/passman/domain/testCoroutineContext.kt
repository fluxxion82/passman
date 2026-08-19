package ai.passman.domain

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.test.StandardTestDispatcher

actual val testCoroutineContext: CoroutineContext
    get() = StandardTestDispatcher()

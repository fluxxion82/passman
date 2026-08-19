package ai.passman.domain

import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher

@OptIn(ExperimentalCoroutinesApi::class)
actual val testCoroutineContext: CoroutineContext
    get() = StandardTestDispatcher()

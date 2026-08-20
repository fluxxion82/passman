package ai.passman.crypto.vault

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * Pins the contract that matters when a [VaultFailure.Malformed] crosses a coroutine boundary:
 * whatever the caller catches — the original instance, or a copy made by kotlinx.coroutines
 * stack trace recovery — [VaultFailure.Malformed.legacyKeyUnavailable] must survive, because
 * callers switch recovery guidance on it ("restore the identity store" vs "restore the vault").
 *
 * Stack trace recovery copies exceptions on the catching side of `async`/`await` and similar
 * boundaries. Before `copyForStackTraceRecovery` existed, Malformed's (String, Throwable?,
 * Boolean) constructor was invisible to the reflective copier, so recovery silently skipped it;
 * a future copier heuristic that DID find a partial constructor would have defaulted the flag
 * to false. The `StackTraceRecoverable` implementation makes the copy explicit either way.
 *
 * The identity assertion below is deliberately loose: whether a copy happens at all depends on
 * the kotlinx.coroutines version consulting the 2.4.20 stdlib interface. The test documents the
 * observed behaviour instead of demanding one, and fails only if the flag or message is lost.
 */
class VaultFailureRecoveryTest {

    @Test
    fun legacyKeyFlagSurvivesCrossingACoroutineBoundary() = runBlocking {
        val original = VaultFailure.Malformed(
            message = "legacy envelope, identity store missing",
            legacyKeyUnavailable = true,
        )
        // supervisorScope: without it the failed async cancels the test scope and the exception
        // escapes runBlocking even though await() is caught.
        val caught = supervisorScope {
            try {
                async(Dispatchers.Default) { throw original }.await()
            } catch (e: VaultFailure.Malformed) {
                e
            }
        }
        assertTrue(caught.legacyKeyUnavailable)
        assertEquals("legacy envelope, identity store missing", caught.message)
        if (caught !== original) {
            // Recovery produced a copy: it must chain back to the original so no trace is lost.
            assertSame(original, caught.cause)
        }
    }

    @Test
    fun explicitCopyCarriesFlagAndChainsOriginal() {
        val original = VaultFailure.Malformed("bad magic", legacyKeyUnavailable = true)
        val copy = original.copyForStackTraceRecovery()
        assertTrue(copy.legacyKeyUnavailable)
        assertEquals(original.message, copy.message)
        assertSame(original, copy.cause)
    }
}

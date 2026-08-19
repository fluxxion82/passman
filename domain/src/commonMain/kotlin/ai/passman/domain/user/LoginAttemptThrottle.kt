package ai.passman.domain.user

import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeMark
import kotlin.time.TimeSource

/**
 * Consecutive-failure cooldown for the unlock screen. The vault's real brute-force defense is the
 * KDF cost on the file itself; this only keeps the UI from being a free guessing oracle, so it is
 * deliberately in-memory — a process restart clears it.
 */
class LoginAttemptThrottle(
    private val timeSource: TimeSource = TimeSource.Monotonic,
) {
    private var failures = 0
    private var lastFailure: TimeMark? = null

    fun cooldownRemaining(): Duration {
        val mark = lastFailure ?: return Duration.ZERO
        if (failures < FREE_ATTEMPTS) return Duration.ZERO
        val doublings = failures - FREE_ATTEMPTS
        val cooldown = BASE_COOLDOWN * (1 shl doublings.coerceAtMost(MAX_DOUBLINGS))
        return (cooldown.coerceAtMost(MAX_COOLDOWN) - mark.elapsedNow()).coerceAtLeast(Duration.ZERO)
    }

    fun recordFailure() {
        failures++
        lastFailure = timeSource.markNow()
    }

    fun recordSuccess() {
        failures = 0
        lastFailure = null
    }

    companion object {
        const val FREE_ATTEMPTS = 5
        val BASE_COOLDOWN = 30.seconds
        val MAX_COOLDOWN = 5.minutes

        // 1 shl anything past this overflows no matter the cap; 2^5 * 30s already exceeds MAX_COOLDOWN.
        private const val MAX_DOUBLINGS = 5
    }
}

package ai.passman.domain.user

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TestTimeSource

class LoginAttemptThrottleTest {
    private val time = TestTimeSource()
    private val throttle = LoginAttemptThrottle(timeSource = time)

    private fun fail(times: Int) = repeat(times) { throttle.recordFailure() }

    @Test
    fun `no failures means no cooldown`() {
        assertEquals(Duration.ZERO, throttle.cooldownRemaining())
    }

    @Test
    fun `four failures stay free`() {
        fail(4)
        assertEquals(Duration.ZERO, throttle.cooldownRemaining())
    }

    @Test
    fun `fifth failure starts a thirty second cooldown`() {
        fail(5)
        assertEquals(30.seconds, throttle.cooldownRemaining())
    }

    @Test
    fun `cooldown counts down as time passes`() {
        fail(5)
        time += 10.seconds
        assertEquals(20.seconds, throttle.cooldownRemaining())
    }

    @Test
    fun `cooldown expires`() {
        fail(5)
        time += 30.seconds
        assertEquals(Duration.ZERO, throttle.cooldownRemaining())
    }

    @Test
    fun `each further failure doubles the cooldown`() {
        fail(6)
        assertEquals(60.seconds, throttle.cooldownRemaining())
    }

    @Test
    fun `cooldown caps at five minutes`() {
        fail(10)
        assertEquals(5.minutes, throttle.cooldownRemaining())
    }

    @Test
    fun `success resets the counter`() {
        fail(5)
        throttle.recordSuccess()
        assertEquals(Duration.ZERO, throttle.cooldownRemaining())
        fail(4)
        assertEquals(Duration.ZERO, throttle.cooldownRemaining())
    }
}

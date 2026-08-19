package ai.passman.platform.service

import ai.passman.platform.prefs.EncryptionSettingsFactory
import ai.passman.platform.prefs.impl.ExpiryAwareClipboardPreferences
import ai.passman.platform.prefs.impl.LocalClipboardPreferences
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.settings.model.ClipboardExpiry
import ai.passman.domain.settings.repository.ClipboardPreferences
import com.russhwolf.settings.MapSettings
import kotlin.coroutines.CoroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest

/**
 * The expiry exists so a password does not sit on the system clipboard forever. The rule that
 * matters more than the expiry itself is the one that keeps it from doing harm: Passman clears
 * *only* a clip it still owns. A user who copied a shipping address, a URL or another app's
 * one-time code in the meantime must find it intact — losing someone else's clipboard is a worse
 * bug than a password lingering for another minute.
 *
 * Ownership, not content. The clip somebody else put there is theirs even when the text is
 * identical to what Passman wrote, and deciding by comparison would both get that case wrong and
 * put an Android "pasted from your clipboard" notification on screen to do it. Nothing in the
 * clipboard contract can read the clipboard at all any more, which is itself asserted below.
 *
 * These drive the real [ExpiringClipboard]; only the system clipboard itself is faked, so the
 * timer, the cancellation and the ownership rule under test are the shipping ones.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ClipboardExpiryTest {

    private val expiry = 30.seconds

    private fun TestScope.newClipboard(
        clipboard: SystemClipboard,
        preferences: ClipboardPreferences = FakePreferences(ClipboardExpiry(enabled = true, duration = expiry)),
    ) = ExpiringClipboard(clipboard = clipboard, preferences = preferences, scope = backgroundScope)

    /** Moves virtual time to exactly `now + duration`, running whatever is due at that instant. */
    private fun TestScope.elapse(duration: Duration) {
        advanceTimeBy(duration)
        runCurrent()
    }

    /**
     * The scheduled clear and the clip it is scheduled for are deliberately unpublished, so
     * reflection is the only way to watch them being dropped. Reading private state is acceptable
     * here precisely because the *absence* of a public surface is part of what is under test.
     */
    private fun ExpiringClipboard.field(name: String): Any? =
        ExpiringClipboard::class.java.getDeclaredField(name)
            .apply { isAccessible = true }
            .get(this)

    private fun ExpiringClipboard.pendingClear(): Job? = field("pendingClear") as Job?

    private fun ExpiringClipboard.pendingClip(): ClipToken? = field("pendingClip") as ClipToken?

    @Test
    fun `a copied secret is cleared once the expiry elapses`() = runTest {
        val clipboard = FakeClipboard()
        val expiring = newClipboard(clipboard)

        expiring.copy("hunter2")
        assertEquals("hunter2", clipboard.text, "the copy itself must still reach the clipboard")

        elapse(expiry - 1.seconds)
        assertEquals("hunter2", clipboard.text, "cleared before its deadline; the user never got to paste it")

        elapse(1.seconds)
        assertNull(clipboard.text, "the secret outlived its expiry")
        assertEquals(1, clipboard.clears)
    }

    /**
     * The case the whole design is built around. Nothing here is Passman's to touch any more.
     */
    @Test
    fun `a clipboard the user changed after the copy is left completely alone`() = runTest {
        val clipboard = FakeClipboard()
        val expiring = newClipboard(clipboard)

        expiring.copy("hunter2")
        clipboard.writtenByAnotherApp("14 Coronation Street, Manchester")

        elapse(expiry * 2)

        assertEquals(
            "14 Coronation Street, Manchester",
            clipboard.text,
            "Passman erased a clip it did not put there. Whatever the user copied after their " +
                "password is gone, and they have no way to get it back — the clear must happen " +
                "only while Passman still owns the clip.",
        )
        assertEquals(0, clipboard.clears, "no clear may be issued once the clip stopped being ours")
    }

    /**
     * The clip that content comparison could never get right, and the reason ownership replaced it.
     *
     * Another app puts the *same text* on the clipboard. Byte-for-byte it looks like what Passman
     * wrote; it is not the clip Passman wrote, and clearing it takes away something that now
     * belongs to the user. A password manager, a shell history line, a second device's sync — text
     * repeats, and "looks like ours" is not "is ours".
     */
    @Test
    fun `an identical clip written by another app is not ours and is left alone`() = runTest {
        val clipboard = FakeClipboard()
        val expiring = newClipboard(clipboard)

        expiring.copy("hunter2")
        clipboard.writtenByAnotherApp("hunter2")

        elapse(expiry)

        assertEquals(
            "hunter2",
            clipboard.text,
            "a clip somebody else placed was cleared because its text matched — that is the " +
                "content comparison this design exists to replace",
        )
        assertEquals(0, clipboard.clears)
    }

    /**
     * Ownership cannot always be established: Android declines to describe the clip while Passman
     * is in the background, and AWT ownership can be reported late. Unknown is not "unchanged" —
     * with no proof the clip is still ours, the safe direction is to leave it.
     */
    @Test
    fun `a clip whose ownership cannot be established at the deadline is left alone`() = runTest {
        val clipboard = FakeClipboard()
        val expiring = newClipboard(clipboard)

        expiring.copy("hunter2")
        clipboard.ownershipKnowable = false

        elapse(expiry)

        assertEquals(0, clipboard.clears, "unproven ownership is not proven ownership")
        assertEquals("hunter2", clipboard.text)
    }

    /**
     * Two copies in quick succession. The mutation this kills is leaving the first timer running:
     * it would still own the *current* clip at its deadline, and the second clip would be wiped ten
     * seconds early while the user is still pasting it. Ownership does not catch that one — only
     * cancelling the old timer does.
     */
    @Test
    fun `a second copy cancels the first timer and the newer clip lives to its own deadline`() = runTest {
        val clipboard = FakeClipboard()
        val expiring = newClipboard(clipboard)

        expiring.copy("first-secret")
        elapse(20.seconds)
        expiring.copy("second-secret")

        // t = 30s: the first copy's deadline. Only the second clip exists now, and it has 20s left.
        elapse(10.seconds)
        assertEquals(
            "second-secret",
            clipboard.text,
            "the first copy's timer survived and took the second clip with it, 20 seconds early",
        )
        assertEquals(0, clipboard.clears)

        // t = 50s: the second copy's own deadline.
        elapse(20.seconds)
        assertNull(clipboard.text)
        assertEquals(1, clipboard.clears, "exactly one clear, from exactly one pending timer")
    }

    /**
     * Opt-out means opt-out: no timer, and nothing asked of the clipboard afterwards either.
     */
    @Test
    fun `with the expiry disabled nothing is scheduled and the clipboard is never questioned`() = runTest {
        val clipboard = FakeClipboard()
        val expiring = newClipboard(
            clipboard,
            preferences = FakePreferences(ClipboardExpiry(enabled = false, duration = expiry)),
        )

        expiring.copy("hunter2")

        elapse(10.minutes)

        assertEquals("hunter2", clipboard.text, "the copy must still work with the expiry turned off")
        assertEquals(0, clipboard.clears)
        assertEquals(0, clipboard.ownershipChecks)
        assertNull(expiring.pendingClip(), "nothing was scheduled, so no clip should be held")
        assertNull(expiring.pendingClear())
    }

    @Test
    fun `the tuned duration is the one that is honoured`() = runTest {
        val clipboard = FakeClipboard()
        val expiring = newClipboard(
            clipboard,
            preferences = FakePreferences(ClipboardExpiry(enabled = true, duration = 5.minutes)),
        )

        expiring.copy("hunter2")

        elapse(expiry)
        assertEquals("hunter2", clipboard.text, "the default deadline was used instead of the stored one")

        elapse(5.minutes)
        assertNull(clipboard.text)
    }

    /**
     * The previous design kept a `CharArray` copy of the password to compare against at the
     * deadline, and had to wipe it on every path out. Ownership needs no copy: there is nothing to
     * wipe, nothing to forget on a cancelled scope, and no second place the password lives while
     * the clear is pending. This fails the moment a field capable of holding one comes back.
     */
    @Test
    fun `no copy of the password is kept while the clear is pending`() = runTest {
        val clipboard = FakeClipboard()
        val expiring = newClipboard(clipboard)

        expiring.copy("hunter2")
        assertNotNull(expiring.pendingClip(), "the clear has nothing to act on")

        assertEquals(
            emptyList(),
            ExpiringClipboard::class.java.declaredFields
                .filterNot { it.isSynthetic }
                .filter { it.type == CharArray::class.java || it.type == String::class.java }
                .map { it.name },
            "the coordinator declares a field that can hold the password itself",
        )
        assertEquals(
            emptyList(),
            ExpiringClipboard::class.java.declaredFields
                .filterNot { it.isSynthetic }
                .filter { it.apply { isAccessible = true }.get(expiring)?.toString()?.contains("hunter2") == true }
                .map { it.name },
            "the password is reachable from the coordinator's own state",
        )
    }

    /**
     * The clipboard contract itself. Reading a clip another app wrote raises the Android 12+
     * "Passman pasted from your clipboard" notification, and it does so in exactly the case where
     * Passman has decided to touch nothing — so the read is not merely unused here, it does not
     * exist. Adding one back to make some future decision easier has to be a deliberate act that
     * fails this first.
     */
    @Test
    fun `nothing in the clipboard contract can read what is on the clipboard`() {
        assertEquals(
            setOf("write", "clear"),
            SystemClipboard::class.java.declaredMethods.map { it.name }.toSet(),
        )
        assertEquals(
            setOf("stillOurs"),
            ClipToken::class.java.declaredMethods.map { it.name }.toSet(),
        )
    }

    /**
     * Finding 2. Persisting the flag is not enough: the timer that is already running has to hear
     * about it, or the user turns the setting off and watches their clipboard be emptied anyway a
     * few seconds later.
     *
     * The assertions immediately after the write are the ones that matter. Severing the
     * notification — dropping the `onExpiryDisabled` call from
     * [ExpiryAwareClipboardPreferences] — leaves the timer scheduled and fails them here, where the
     * coordinator's own fire-time re-read could otherwise quietly cover for the missing hand-off.
     */
    @Test
    fun `turning the expiry off cancels the clear that is already pending`() = runTest {
        val clipboard = FakeClipboard()
        val stored = FakePreferences(ClipboardExpiry(enabled = true, duration = expiry))
        val expiring = newClipboard(clipboard, stored)
        val preferences = ExpiryAwareClipboardPreferences(stored = stored, clipboard = expiring)

        expiring.copy("hunter2")
        elapse(10.seconds)
        assertNotNull(expiring.pendingClear(), "there is no pending clear to cancel; the test proves nothing")

        preferences.setExpiry(ClipboardExpiry(enabled = false, duration = expiry))

        assertNull(expiring.pendingClear(), "the clear the user just opted out of is still scheduled")
        assertNull(expiring.pendingClip(), "the clip the cancelled clear was scheduled for is still held")

        elapse(expiry * 2)

        assertEquals("hunter2", clipboard.text, "opting out did not stop the clear that was already running")
        assertEquals(0, clipboard.clears)
        assertEquals(0, clipboard.ownershipChecks, "a cancelled clear must not question the clipboard either")
    }

    /**
     * Defence in depth for the same finding, one layer down: the setting says off by the time the
     * timer fires, but nobody told the coordinator. That is what a caller bypassing the decorator,
     * or a second process writing the same store, leaves behind.
     */
    @Test
    fun `a pending clear that was never told the expiry was turned off still declines to fire`() = runTest {
        val clipboard = FakeClipboard()
        val stored = FakePreferences(ClipboardExpiry(enabled = true, duration = expiry))
        val expiring = newClipboard(clipboard, stored)

        expiring.copy("hunter2")
        stored.setExpiry(ClipboardExpiry(enabled = false, duration = expiry))

        elapse(expiry)

        assertEquals("hunter2", clipboard.text)
        assertEquals(0, clipboard.clears)
    }

    /**
     * Finding 5. Reading the stored setting is a suspending call, and two copies made in quick
     * succession can have those reads resume in the opposite order — the first copy's read
     * finishing *after* the second's. Whichever copy resumes last would then write the clipboard
     * last and cancel the other's timer, so the older password would win and sit there under the
     * newer one's deadline.
     *
     * The gate forces exactly that interleaving. Taking the lock before the read is what makes it
     * impossible: the second copy cannot get past the coordinator until the first has finished
     * with it, in the order they were called.
     */
    @Test
    fun `two copies whose preference reads resume out of order still leave the newer clip`() = runTest {
        val clipboard = FakeClipboard()
        val preferences = GatedPreferences(ClipboardExpiry(enabled = true, duration = expiry))
        val gate = CompletableDeferred<Unit>()
        preferences.gateRead(index = 0, gate = gate)
        val expiring = newClipboard(clipboard, preferences)

        launch { expiring.copy("first-secret") }
        runCurrent()
        launch { expiring.copy("second-secret") }
        runCurrent()

        // Whatever is on the clipboard now, it is not the second copy's: that one is parked behind
        // the first, which is still inside the coordinator on its stored-setting read. With the
        // read taken before the lock the second copy would have overtaken it and written already.
        assertNotEquals("second-secret", clipboard.text)

        gate.complete(Unit)
        runCurrent()

        assertEquals(
            "second-secret",
            clipboard.text,
            "the first copy resumed last and overwrote the newer clip with the older password",
        )

        // ...and the surviving clip lives to its *own* deadline, under exactly one timer.
        elapse(expiry)
        assertNull(clipboard.text)
        assertEquals(1, clipboard.clears, "exactly one clear, from exactly one pending timer")
    }

    @Test
    fun `an install that has never touched the setting gets the expiry on at thirty seconds`() = runBlocking {
        val preferences = LocalClipboardPreferences(
            encryptedFactory = MapSettingsFactory,
            coroutinesContextFacade = UnconfinedFacade,
        )

        assertEquals(ClipboardExpiry(enabled = true, duration = 30.seconds), preferences.getExpiry())
    }

    @Test
    fun `a stored expiry round-trips, so the duration can be tuned without a format change`() = runBlocking {
        val settings = MapSettings()
        val preferences = LocalClipboardPreferences(
            encryptedFactory = object : EncryptionSettingsFactory {
                override fun createEncrypted(name: String) = settings
            },
            coroutinesContextFacade = UnconfinedFacade,
        )

        preferences.setExpiry(ClipboardExpiry(enabled = false, duration = 90.seconds))

        assertEquals(ClipboardExpiry(enabled = false, duration = 90.seconds), preferences.getExpiry())
        // A second reader over the same store sees it too: the value is persisted, not remembered.
        val reopened = LocalClipboardPreferences(
            encryptedFactory = object : EncryptionSettingsFactory {
                override fun createEncrypted(name: String) = settings
            },
            coroutinesContextFacade = UnconfinedFacade,
        )
        assertEquals(ClipboardExpiry(enabled = false, duration = 90.seconds), reopened.getExpiry())
    }

    @Test
    fun `a stored duration of zero falls back to the default rather than clearing instantly`() = runBlocking {
        val settings = MapSettings()
        val preferences = LocalClipboardPreferences(
            encryptedFactory = object : EncryptionSettingsFactory {
                override fun createEncrypted(name: String) = settings
            },
            coroutinesContextFacade = UnconfinedFacade,
        )

        preferences.setExpiry(ClipboardExpiry(enabled = true, duration = Duration.ZERO))

        assertEquals(ClipboardExpiry.Default.duration, preferences.getExpiry().duration)
    }

    private object MapSettingsFactory : EncryptionSettingsFactory {
        override fun createEncrypted(name: String) = MapSettings()
    }

    private object UnconfinedFacade : CoroutinesContextFacade {
        override val io: CoroutineContext = Dispatchers.Unconfined
        override val main: CoroutineContext = Dispatchers.Unconfined
        override val default: CoroutineContext = Dispatchers.Unconfined
        override val unconfined: CoroutineContext = Dispatchers.Unconfined
        override val errorHandler: CoroutineContext = CoroutineExceptionHandler { _, _ -> }
    }
}

private open class FakePreferences(private var expiry: ClipboardExpiry) : ClipboardPreferences {
    override suspend fun getExpiry(): ClipboardExpiry = expiry

    override suspend fun setExpiry(expiry: ClipboardExpiry) {
        this.expiry = expiry
    }
}

/**
 * A store whose reads can be parked on demand, so the ordering of two copies' suspending
 * preference reads is a property of the test rather than of the scheduler's mood.
 */
private class GatedPreferences(expiry: ClipboardExpiry) : FakePreferences(expiry) {
    private val gates = mutableMapOf<Int, CompletableDeferred<Unit>>()
    private var reads = 0

    /** Makes the read with this zero-based [index] wait for [gate] before it answers. */
    fun gateRead(index: Int, gate: CompletableDeferred<Unit>) {
        gates[index] = gate
    }

    override suspend fun getExpiry(): ClipboardExpiry {
        gates[reads++]?.await()
        return super.getExpiry()
    }
}

/**
 * Stands in for the AWT and Android clipboards, including the two cases that decide whether a clear
 * is safe: a clip somebody else placed (identical text or not), and a platform that will not say
 * who owns the clip at all.
 */
private class FakeClipboard : SystemClipboard {
    private var current: FakeClip? = null

    var clears = 0
        private set

    /** How many times the coordinator asked whether the clip was still ours. */
    var ownershipChecks = 0
        private set

    /** Flip to false to model a platform that declines to say who owns the current clip. */
    var ownershipKnowable = true

    val text: String? get() = current?.text

    override fun write(text: String): ClipToken = FakeClip(text).also { current = it }

    override fun clear() {
        clears++
        current = null
    }

    /**
     * Somebody else takes the clipboard. The text may be anything, *including* exactly what Passman
     * wrote: the clip is a different clip either way.
     */
    fun writtenByAnotherApp(text: String) {
        current = FakeClip(text)
    }

    private inner class FakeClip(val text: String) : ClipToken {
        override fun stillOurs(): Boolean {
            ownershipChecks++
            return ownershipKnowable && current === this
        }
    }
}

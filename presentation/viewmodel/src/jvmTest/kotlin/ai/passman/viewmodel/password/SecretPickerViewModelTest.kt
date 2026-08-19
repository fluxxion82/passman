package ai.passman.viewmodel.password

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.GetPasswordEntries
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.repository.PasswordRepository
import androidx.lifecycle.ViewModelStore
import java.lang.reflect.Modifier
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain

/**
 * The picker is the *only* way a stored password reaches a PGP or keystore field, so what it must
 * not do matters as much as what it does: it never hands a password to the clipboard, never lists
 * one, and delivers the one the user picked to whoever is listening at the moment of the tap
 * without keeping a copy anyone can read back.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SecretPickerViewModelTest {

    private val repository = FakePasswordRepository()
    private val events = FakePasswordEventPersistence()
    private val getPasswordEntries = GetPasswordEntries(repository, events)

    @BeforeTest
    fun setup() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        repository.entries = listOf(GMAIL, BANK, VPN)
    }

    @AfterTest
    fun tearDown() {
        Dispatchers.resetMain()
    }

    private fun newVm() = SecretPickerViewModel(getPasswordEntries = getPasswordEntries)

    /**
     * Subscribes to [SecretPickerViewModel.result] now and returns the live, growing list of what
     * arrives. Attaching before the action under test is the point: results are events, so a
     * collector only ever sees what is emitted while it is subscribed.
     */
    private fun TestScope.resultsFrom(vm: SecretPickerViewModel): List<SecretPickerResult> {
        val received = mutableListOf<SecretPickerResult>()
        backgroundScope.launch(UnconfinedTestDispatcher(testScheduler)) { vm.result.toList(received) }
        runCurrent()
        return received
    }

    /**
     * The session's entries carry passwords and are deliberately unpublished, so reflection is the
     * only way to watch them being cleared. Reading a private field is acceptable here precisely
     * because the field's *absence of a public surface* is the property under test.
     */
    private fun SecretPickerViewModel.loadedEntries(): List<*> =
        SecretPickerViewModel::class.java.getDeclaredField("loadedEntries")
            .apply { isAccessible = true }
            .get(this) as List<*>

    @Test
    fun `nothing is read from the vault until the picker is opened`() = runTest {
        val vm = newVm()
        val results = resultsFrom(vm)

        assertEquals(0, repository.readCount)
        assertEquals("", vm.query.value)
        assertTrue(vm.rows.value.isEmpty())
        assertTrue(results.isEmpty())
        assertFalse(vm.visible.value)
    }

    @Test
    fun `opening lists every entry by name and username, and never its password`() = runTest {
        val vm = newVm()
        vm.openPicker()

        assertTrue(vm.visible.value)
        // GetPasswordEntries sorts by entry name, case-insensitively.
        assertEquals(listOf("u-bank", "u-gmail", "u-vpn"), vm.rows.value.map { it.uuid })
        assertEquals(listOf("Bank", "gmail", "work vpn"), vm.rows.value.map { it.entryName })
        assertEquals(listOf("GEORGE", "ada@gmail.com", "ada"), vm.rows.value.map { it.username })

        // A row that carries the secret would leak it into every list render and every log line
        // that touches the state. The row type is allowed exactly these three fields.
        assertEquals(
            setOf("uuid", "entryName", "username"),
            // Static fields are the Compose compiler's `$stable`, not state the row carries.
            SecretPickerRow::class.java.declaredFields
                .filterNot { it.isSynthetic || Modifier.isStatic(it.modifiers) }
                .map { it.name }
                .toSet(),
        )
        assertFalse(vm.rows.value.toString().contains("hunter2"))
    }

    @Test
    fun `search matches the entry name case-insensitively when the username does not match`() = runTest {
        val vm = newVm()
        vm.openPicker()

        // Both fixtures match on the *name only*, so a filter that dropped the name clause and kept
        // the username one would find nothing. Lower-case query against a capitalised name...
        vm.onQueryChanged("ban")

        assertEquals("ban", vm.query.value)
        assertEquals(listOf("u-bank"), vm.rows.value.map { it.uuid })
        assertFalse(BANK.username.contains("ban", ignoreCase = true))

        // ...and upper-case query against a lower-case name, so neither direction of the
        // case-insensitivity can be dropped either.
        vm.onQueryChanged("VPN")

        assertEquals(listOf("u-vpn"), vm.rows.value.map { it.uuid })
        assertFalse(VPN.username.contains("VPN", ignoreCase = true))
    }

    @Test
    fun `search matches the username case-insensitively even when the name does not match`() = runTest {
        val vm = newVm()
        vm.openPicker()

        // "george" appears only in the Bank entry's username, and only in upper case there. A
        // name-only filter, or a case-sensitive one, finds nothing here.
        vm.onQueryChanged("george")

        assertEquals(listOf("u-bank"), vm.rows.value.map { it.uuid })
        assertFalse(BANK.entryName.contains("george", ignoreCase = true))
    }

    @Test
    fun `a blank query lists everything again`() = runTest {
        val vm = newVm()
        vm.openPicker()
        vm.onQueryChanged("ban")
        assertEquals(1, vm.rows.value.size)

        vm.onQueryChanged("")

        assertEquals(3, vm.rows.value.size)
    }

    @Test
    fun `selection hands the chosen password to the listening screen exactly once`() = runTest {
        val vm = newVm()
        val results = resultsFrom(vm)
        vm.openPicker()

        vm.onEntrySelected("u-gmail")

        val delivered = assertIs<SecretPickerResult.Selected>(results.single())
        assertEquals("hunter2", delivered.password)

        assertFalse(vm.visible.value)
        assertEquals("", vm.query.value)
        assertTrue(vm.rows.value.isEmpty())
        assertTrue(vm.loadedEntries().isEmpty())
    }

    /**
     * The mutation this kills: turning [SecretPickerViewModel.result] back into a `StateFlow`, or
     * giving the shared flow any replay at all. Either one hands the password to a host that is
     * recreated after the tap, to a second collector, or to anything that attaches later — the
     * secret would then outlive the session for as long as nobody bothered to clear it.
     */
    @Test
    fun `a screen that starts listening after the selection is never handed the password`() = runTest {
        val vm = newVm()
        vm.openPicker()

        vm.onEntrySelected("u-gmail")

        val late = resultsFrom(vm)
        assertTrue(late.isEmpty())

        // The password is not reachable through any other published surface either.
        assertFalse(vm.rows.value.toString().contains("hunter2"))
        assertTrue(vm.loadedEntries().isEmpty())
    }

    /**
     * The one slot of `extraBufferCapacity` is what lets the emit be non-suspending; this pins that
     * it never becomes a replay cache by the back door. A collector that is subscribed but parked
     * takes the value into the buffer, and then goes away without reading it — the next collector
     * must still get nothing.
     */
    @Test
    fun `a result buffered for a collector that goes away is not handed to the next collector`() = runTest {
        val vm = newVm()
        vm.openPicker()

        val parked = mutableListOf<SecretPickerResult>()
        // A standard dispatcher subscribes when told to, and then stays parked until told to run.
        val parkedCollector = launch(StandardTestDispatcher(testScheduler)) { vm.result.toList(parked) }
        runCurrent()

        vm.onEntrySelected("u-gmail")
        parkedCollector.cancel()
        runCurrent()

        val late = resultsFrom(vm)
        assertTrue(late.isEmpty())
    }

    @Test
    fun `two sessions on the same instance deliver independent results`() = runTest {
        val vm = newVm()
        val results = resultsFrom(vm)

        vm.openPicker()
        vm.onEntrySelected("u-gmail")
        vm.openPicker()
        vm.onEntrySelected("u-bank")

        assertEquals(
            listOf(
                SecretPickerResult.Selected("hunter2"),
                SecretPickerResult.Selected("vault-key"),
            ),
            results,
        )
    }

    @Test
    fun `selecting an entry that is no longer listed yields nothing`() = runTest {
        val vm = newVm()
        val results = resultsFrom(vm)
        vm.openPicker()
        assertTrue(vm.rows.value.any { it.uuid == "u-gmail" })

        // The vault changes under the open list: another screen deletes the entry the user is
        // about to tap, and the tap lands on the row the UI had already drawn.
        repository.entries = listOf(BANK, VPN)
        events.update(PasswordEvent.Deleted("u-gmail"))
        runCurrent()
        assertFalse(vm.rows.value.any { it.uuid == "u-gmail" })

        vm.onEntrySelected("u-gmail")

        // No result at all — handing back a neighbouring entry's password would be worse than
        // nothing, and so would crashing on the stale row.
        assertTrue(results.isEmpty())
        assertTrue(vm.visible.value)
    }

    @Test
    fun `cancelling delivers Cancelled and no secret`() = runTest {
        val vm = newVm()
        val results = resultsFrom(vm)
        vm.openPicker()

        vm.dismissPicker()

        assertEquals(listOf(SecretPickerResult.Cancelled), results)
    }

    @Test
    fun `a screen that starts listening after a cancellation is handed nothing`() = runTest {
        val vm = newVm()
        vm.openPicker()

        vm.dismissPicker()

        assertTrue(resultsFrom(vm).isEmpty())
    }

    /**
     * The dismissal that matters is the one with no selection in it: the user opens the picker,
     * changes their mind, and the vault feed has to stop right there. Without the session teardown
     * the collector stays subscribed, and the next vault change quietly reloads every entry —
     * passwords included — into a view model nobody is looking at any more.
     */
    @Test
    fun `dismissing without selecting stops the vault feed and drops the loaded entries`() = runTest {
        val vm = newVm()
        val results = resultsFrom(vm)
        vm.openPicker()
        vm.onQueryChanged("ban")
        assertTrue(vm.loadedEntries().isNotEmpty())

        vm.dismissPicker()
        events.update(PasswordEvent.Updated)
        runCurrent()

        assertTrue(vm.rows.value.isEmpty())
        assertTrue(vm.loadedEntries().isEmpty())
        assertEquals("", vm.query.value)
        assertFalse(vm.visible.value)

        // Nothing was reloaded, so a uuid that was valid a moment ago now resolves to nothing.
        vm.onEntrySelected("u-gmail")
        assertEquals(listOf(SecretPickerResult.Cancelled), results)
    }

    @Test
    fun `reopening the same instance starts a fresh session`() = runTest {
        val vm = newVm()

        vm.openPicker()
        vm.onQueryChanged("ban")
        vm.onEntrySelected("u-bank")
        vm.dismissPicker()

        // Koin hands out one instance per screen graph, so "fresh" cannot mean "newly constructed".
        vm.openPicker()

        assertEquals("", vm.query.value)
        assertEquals(listOf("u-bank", "u-gmail", "u-vpn"), vm.rows.value.map { it.uuid })
    }

    @Test
    fun `onCleared ends the session and stops the vault feed`() = runTest {
        val vm = newVm()
        vm.openPicker()
        assertTrue(vm.loadedEntries().isNotEmpty())

        ViewModelStore().apply { put("secret-picker", vm) }.clear()
        events.update(PasswordEvent.Updated)
        runCurrent()

        assertTrue(vm.rows.value.isEmpty())
        assertTrue(vm.loadedEntries().isEmpty())
    }

    /**
     * The picker exists so a saved password can reach a tool field *without* the clipboard, so it
     * takes no clipboard dependency at all rather than taking one and declining to call it. There
     * is no fake to inject: the assertion is on the surface that would make a call possible.
     *
     * What this proves: the only thing anyone can hand this class is the vault reader, so no
     * clipboard, settings service or exfiltration sink can be injected — and nothing can be added
     * later without this test noticing. What it cannot prove: a global, a service locator or a
     * platform API reached from inside a method body needs no constructor parameter at all. That
     * risk is carried by review of the (small) body of this class, not by reflection.
     */
    @Test
    fun `the picker is constructible only from the vault reader`() {
        val constructors = SecretPickerViewModel::class.java.declaredConstructors

        assertEquals(1, constructors.size)
        assertEquals(
            listOf(GetPasswordEntries::class.java),
            constructors.single().parameterTypes.toList(),
        )
    }

    private companion object {
        val GMAIL = entry(name = "gmail", username = "ada@gmail.com", password = "hunter2", uuid = "u-gmail")

        /** "ban" matches the *name* only, "george" the *username* only — one clause each. */
        val BANK = entry(name = "Bank", username = "GEORGE", password = "vault-key", uuid = "u-bank")
        val VPN = entry(name = "work vpn", username = "ada", password = "tunnel", uuid = "u-vpn")

        fun entry(name: String, username: String, password: String, uuid: String) = PasswordEntry(
            id = "0",
            entryName = name,
            username = username,
            password = password,
            website = "",
            notes = "",
            dateCreated = 0L,
            uuid = uuid,
        )
    }
}

private class FakePasswordRepository : PasswordRepository {
    var entries: List<PasswordEntry> = emptyList()
    var readCount: Int = 0
        private set

    override suspend fun getPasswordEntries(): List<PasswordEntry> {
        readCount++
        return entries
    }

    override suspend fun addPasswordEntry(entry: AddPassword.EntryData): Boolean = unsupported()
    override suspend fun updatePasswordEntry(entry: PasswordEntry): Boolean = unsupported()
    override suspend fun deletePasswordEntry(passwordUuid: String): Boolean = unsupported()
    override suspend fun deletePasswordEntries(passwordUuids: Collection<String>): Int = unsupported()
    override suspend fun transferPasswordDatabase(hostName: String): Outcome<Unit> = unsupported()
    override suspend fun pushPasswordDatabase(hostName: String): Outcome<Unit> = unsupported()
    override suspend fun pullPasswordDatabase(hostName: String): Outcome<Unit> = unsupported()

    private fun unsupported(): Nothing =
        throw UnsupportedOperationException("the picker only reads the vault")
}

private class FakePasswordEventPersistence : PasswordEventPersistence {
    private val events = MutableSharedFlow<PasswordEvent>(extraBufferCapacity = 8)

    override fun events(): Flow<PasswordEvent> = events

    override suspend fun update(event: PasswordEvent) {
        events.emit(event)
    }
}

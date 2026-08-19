package ai.passman.domain.keystore

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.keystore.model.KeyStoreInfo
import ai.passman.domain.keystore.model.KeyStoreType
import ai.passman.domain.keystore.model.KeystoreEvent
import ai.passman.domain.keystore.model.KeystoreKeyAlgorithm
import ai.passman.domain.keystore.persistence.KeystoreEventPersistence
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.FakePasswordRepository
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.password.exception.PasswordFailure
import ai.passman.domain.user.FakeLoggedInUserPreferences
import ai.passman.domain.user.GeneratePassword
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

class EnsureDefaultKeystoreTest {

    private val userName = "alice"
    private val storePath = "/local/keystore/alice"
    private val storeFileName = "${EnsureDefaultKeystore.KEYSTORE_NAME}.pfx"

    private class RecordingKeystoreEvents : KeystoreEventPersistence {
        val updates = mutableListOf<KeystoreEvent>()
        override fun events(): Flow<KeystoreEvent> = emptyFlow()
        override suspend fun update(event: KeystoreEvent) {
            updates += event
        }
    }

    private class RecordingPasswordEvents : PasswordEventPersistence {
        val updates = mutableListOf<PasswordEvent>()
        override fun events(): Flow<PasswordEvent> = emptyFlow()
        override suspend fun update(event: PasswordEvent) {
            updates += event
        }
    }

    private class Harness(
        keystoreRepository: FakeKeystoreRepository,
        passwordRepository: FakePasswordRepository,
        userPreferences: UserPreferences = FakeLoggedInUserPreferences("alice"),
    ) {
        val keystoreRepository = keystoreRepository
        val passwordRepository = passwordRepository
        val keystorePreferences = FakeKeystorePreferences()
        val keystoreEvents = RecordingKeystoreEvents()
        val passwordEvents = RecordingPasswordEvents()
        val useCase = EnsureDefaultKeystore(
            keystoreRepository = keystoreRepository,
            passwordRepository = passwordRepository,
            keystorePreferences = keystorePreferences,
            userPreferences = userPreferences,
            generatePassword = GeneratePassword(),
            createKeyStore = CreateKeyStore(keystoreRepository, keystoreEvents),
            deleteKeystore = DeleteKeystore(keystoreRepository, keystoreEvents),
            addPassword = AddPassword(passwordRepository, passwordEvents),
        )
    }

    private fun existingStore(name: String = "mine.pfx") = KeyStoreInfo(
        path = storePath,
        name = name,
        keystorePassword = "",
        keyList = listOf(),
        type = KeyStoreType.PKCS12,
    )

    private fun existingEntry(name: String) = PasswordEntry(
        id = "1",
        entryName = name,
        username = "someone",
        password = "secret",
        website = "",
        notes = "",
        dateCreated = 1000L,
        uuid = "existing-entry",
    )

    @Test
    fun aFreshAccountGetsTheStarterKeystoreAndItsVaultEntry() = runTest {
        val harness = Harness(
            FakeKeystoreRepository(
                allKeystores = { emptyList() },
                create = { request ->
                    Outcome.Success(existingStore(name = storeFileName).copy(keystorePassword = request.keystorePassword))
                },
            ),
            FakePasswordRepository(entries = { emptyList() }, add = { true }),
        )

        val outcome = harness.useCase(Unit)

        assertEquals(true, assertIs<Outcome.Success<Boolean>>(outcome).value)

        val request = harness.keystoreRepository.createRequests.single()
        assertEquals(EnsureDefaultKeystore.KEYSTORE_NAME, request.keystoreName)
        assertEquals(EnsureDefaultKeystore.KEY_ALIAS, request.keyAlias)
        assertEquals(KeyStoreType.PKCS12, request.keystoreType)
        assertEquals(KeystoreKeyAlgorithm.RSA, request.keyAlgorithm, "the CreateKeyStore screen's default")
        assertEquals(request.keystorePassword, request.aliasPassword, "one password to look up, not two")
        // High-entropy but user-typeable: they will read it from the vault and type it in.
        assertEquals(24, request.keystorePassword.length)
        val alphabet = GeneratePassword.UPPER + GeneratePassword.LOWER + GeneratePassword.NUM + GeneratePassword.SYMBOLS
        assertTrue(request.keystorePassword.all { it in alphabet })

        val entry = harness.passwordRepository.added.single()
        assertEquals(EnsureDefaultKeystore.entryName(userName), entry.entryName)
        assertEquals(request.keystorePassword, entry.password)
        // The username field names the artifact the password opens.
        assertEquals(storeFileName, entry.userName)
        assertTrue(entry.notes.isNotBlank(), "the entry must explain it was auto-created")

        assertTrue(harness.keystorePreferences.isFlagSet(userName))
        assertEquals(listOf<KeystoreEvent>(KeystoreEvent.Created), harness.keystoreEvents.updates)
        assertEquals(listOf<PasswordEvent>(PasswordEvent.Created), harness.passwordEvents.updates)
    }

    @Test
    fun anAccountWithKeystoresGetsTheFlagAndNoStarterKeystore() = runTest {
        val harness = Harness(
            FakeKeystoreRepository(allKeystores = { listOf(existingStore()) }),
            FakePasswordRepository(),
        )

        val outcome = harness.useCase(Unit)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertTrue(harness.keystoreRepository.createRequests.isEmpty())
        assertTrue(harness.passwordRepository.added.isEmpty())
        assertTrue(harness.keystorePreferences.isFlagSet(userName), "so deletion of those keystores stays final")
    }

    @Test
    fun anExistingStarterEntryGetsTheFlagAndNoStarterKeystore() = runTest {
        // The entry can arrive by vault sync before this device ever created anything.
        val harness = Harness(
            FakeKeystoreRepository(allKeystores = { emptyList() }),
            FakePasswordRepository(
                entries = { listOf(existingEntry(EnsureDefaultKeystore.entryName(userName))) },
            ),
        )

        val outcome = harness.useCase(Unit)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertTrue(harness.keystoreRepository.createRequests.isEmpty())
        assertTrue(harness.passwordRepository.added.isEmpty())
        assertTrue(harness.keystorePreferences.isFlagSet(userName))
    }

    @Test
    fun aLegacyBareNameEntryAlsoSettlesTheGuard() = runTest {
        // Earlier builds wrote the bare base name, then a parenthesised profile variant.
        val harness = Harness(
            FakeKeystoreRepository(allKeystores = { emptyList() }),
            FakePasswordRepository(
                entries = {
                    listOf(
                        existingEntry(EnsureDefaultKeystore.ENTRY_NAME),
                        existingEntry("${EnsureDefaultKeystore.ENTRY_NAME} ($userName)"),
                    )
                },
            ),
        )

        val outcome = harness.useCase(Unit)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertTrue(harness.keystoreRepository.createRequests.isEmpty())
    }

    @Test
    fun aSetFlagShortCircuitsBeforeTouchingAnyRepository() = runTest {
        // Every repository method is unconfigured, so any touch fails the test loudly.
        val harness = Harness(FakeKeystoreRepository(), FakePasswordRepository())
        harness.keystorePreferences.presetFlag(userName)

        val outcome = harness.useCase(Unit)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
    }

    @Test
    fun aFailedCreationWritesNoVaultEntryAndLeavesTheFlagUnset() = runTest {
        val harness = Harness(
            FakeKeystoreRepository(
                allKeystores = { emptyList() },
                create = { Outcome.Error("disk full", ai.passman.domain.keystore.exception.KeystoreFailure.CreateKeystore) },
            ),
            FakePasswordRepository(entries = { emptyList() }),
        )

        val outcome = harness.useCase(Unit)

        assertIs<Outcome.Error>(outcome)
        assertTrue(harness.passwordRepository.added.isEmpty(), "no entry may promise a keystore that does not exist")
        assertFalse(harness.keystorePreferences.isFlagSet(userName), "so the next login retries")
    }

    @Test
    fun aFailedVaultEntryDeletesTheJustCreatedKeystore() = runTest {
        val harness = Harness(
            FakeKeystoreRepository(
                allKeystores = { emptyList() },
                create = { request ->
                    Outcome.Success(existingStore(name = storeFileName).copy(keystorePassword = request.keystorePassword))
                },
                delete = { _, _, _ -> true },
            ),
            FakePasswordRepository(entries = { emptyList() }, add = { false }),
        )

        val outcome = harness.useCase(Unit)

        assertIs<Outcome.Error>(outcome)
        val request = harness.keystoreRepository.createRequests.single()
        assertEquals(2, harness.passwordRepository.added.size, "one retry before giving the keystore up")
        val (path, name, password) = harness.keystoreRepository.deleteCalls.single()
        assertEquals(storePath, path)
        assertEquals(storeFileName, name)
        assertEquals(request.keystorePassword, password)
        assertFalse(harness.keystorePreferences.isFlagSet(userName), "so the next login retries")
    }

    @Test
    fun anUnreadableVaultAbortsWithoutProvisioningOrFlagging() = runTest {
        // getPasswordEntries flattens an unreadable vault to an empty list; the guard uses the
        // Outcome-returning read instead, because that vault may already HOLD the entry.
        val harness = Harness(
            FakeKeystoreRepository(allKeystores = { emptyList() }),
            FakePasswordRepository(list = { Outcome.Error("vault unreadable", PasswordFailure.VaultUnreadable) }),
        )

        val outcome = harness.useCase(Unit)

        assertIs<Outcome.Error>(outcome)
        assertTrue(harness.keystoreRepository.createRequests.isEmpty())
        assertFalse(harness.keystorePreferences.isFlagSet(userName), "a readable vault must settle it later")
    }

    @Test
    fun anAnonymousSessionIsRefusedBeforeTouchingAnything() = runTest {
        // Every repository method is unconfigured, so any touch fails the test loudly.
        val harness = Harness(
            FakeKeystoreRepository(),
            FakePasswordRepository(),
            userPreferences = FakeLoggedInUserPreferences(AppUser.Anonymous),
        )

        assertIs<Outcome.Error>(harness.useCase(Unit))
        assertFalse(harness.keystorePreferences.isFlagSet(userName))
    }

    @Test
    fun aCancellationDuringCreationStillCommitsTheWholeSequence() = runTest {
        // The caller's timeout must only ever bound the guard phase. A cancellation delivered
        // while the (blocking, real-world) keygen runs lands AFTER the store is on disk; tearing
        // the sequence apart there would orphan a keystore whose password nobody recorded — and
        // the next login's guards would then flag the account, making the orphan permanent.
        val createEntered = CompletableDeferred<Unit>()
        val releaseCreate = CompletableDeferred<Unit>()
        val harness = Harness(
            FakeKeystoreRepository(
                allKeystores = { emptyList() },
                create = { request ->
                    createEntered.complete(Unit)
                    releaseCreate.await() // the "keygen" runs while the caller cancels
                    Outcome.Success(existingStore(name = storeFileName).copy(keystorePassword = request.keystorePassword))
                },
            ),
            FakePasswordRepository(entries = { emptyList() }, add = { true }),
        )

        val job = launch { harness.useCase(Unit) }
        createEntered.await()
        job.cancel()
        releaseCreate.complete(Unit)
        job.join()

        assertEquals(1, harness.passwordRepository.added.size, "the password must still be recorded")
        assertTrue(harness.keystorePreferences.isFlagSet(userName), "the flag must still be set")
        assertTrue(harness.keystoreRepository.deleteCalls.isEmpty(), "nothing rolled back — the sequence completed")
    }
}

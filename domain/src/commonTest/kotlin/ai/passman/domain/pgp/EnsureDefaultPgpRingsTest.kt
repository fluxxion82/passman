package ai.passman.domain.pgp

import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.FakePasswordRepository
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.model.PasswordEvent
import ai.passman.domain.password.persistence.PasswordEventPersistence
import ai.passman.domain.pgp.exception.PgpFailure
import ai.passman.domain.pgp.model.PgpEvent
import ai.passman.domain.pgp.model.PgpKey
import ai.passman.domain.pgp.model.PgpKeyPair
import ai.passman.domain.pgp.model.PgpKeyType
import ai.passman.domain.pgp.persistence.PgpEventPersistence
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

class EnsureDefaultPgpRingsTest {

    private val userName = "alice"

    private class RecordingPgpEvents : PgpEventPersistence {
        val updates = mutableListOf<PgpEvent>()
        override fun events(): Flow<PgpEvent> = emptyFlow()
        override suspend fun update(event: PgpEvent) {
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
        pgpRepository: FakePgpRepository,
        passwordRepository: FakePasswordRepository,
        userPreferences: UserPreferences = FakeLoggedInUserPreferences("alice"),
    ) {
        val pgpRepository = pgpRepository
        val passwordRepository = passwordRepository
        val pgpPreferences = FakePgpPreferences()
        val pgpEvents = RecordingPgpEvents()
        val passwordEvents = RecordingPasswordEvents()
        val useCase = EnsureDefaultPgpRings(
            pgpRepository = pgpRepository,
            pgpPreferences = pgpPreferences,
            passwordRepository = passwordRepository,
            userPreferences = userPreferences,
            generatePassword = GeneratePassword(),
            addPassword = AddPassword(passwordRepository, passwordEvents),
            pgpEventPersistence = pgpEvents,
        )
    }

    private fun pgpKey(fileName: String, type: PgpKeyType, keyId: Long) = PgpKey(
        fileName = fileName,
        path = "/local/pgp/alice/$fileName",
        type = type,
        keyId = keyId,
        creationTime = 0L,
        expirationTime = null,
        isRevoked = false,
        algorithm = "RSA",
        bitStrength = 4096,
        userIds = listOf(),
        fingerprint = "fp-$keyId",
        isMaster = true,
        isSigningKey = true,
        isEncryptionKey = true,
    )

    /** A keypair with a secret half — what a legacy or synced account owns. */
    private fun someKeyPair() = PgpKeyPair(
        publicKey = pgpKey("passman_public_ring.asc", PgpKeyType.Public, 42L),
        secretKey = pgpKey("passman_secret_ring.asc", PgpKeyType.Secret, 42L),
    )

    /** A public-only key — the shape of the auto-imported developer key. */
    private fun publicOnlyKeyPair() = PgpKeyPair(
        publicKey = pgpKey("passman_developer_public_key.asc", PgpKeyType.Public, 77L),
        secretKey = null,
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

    // ------------------------------------------------------------- RecordFreshRings (signup)

    @Test
    fun recordingFreshRingsWritesTheEntryAndSetsTheFlag() = runTest {
        val harness = Harness(FakePgpRepository(), FakePasswordRepository(add = { true }))

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.RecordFreshRings("ring passphrase"))

        assertEquals(true, assertIs<Outcome.Success<Boolean>>(outcome).value)
        val entry = harness.passwordRepository.added.single()
        assertEquals(EnsureDefaultPgpRings.entryName(userName), entry.entryName)
        assertEquals("ring passphrase", entry.password)
        // The username field names the artifact the passphrase opens.
        assertEquals(EnsureDefaultPgpRings.RINGS_LABEL, entry.userName)
        assertTrue(entry.notes.isNotBlank(), "the entry must explain it was auto-created")
        assertTrue(harness.pgpPreferences.isProvisionedFlagSet(userName))
        assertEquals(0, harness.pgpRepository.deleteDefaultRingCalls)
        assertEquals(listOf<PasswordEvent>(PasswordEvent.Created), harness.passwordEvents.updates)
    }

    @Test
    fun anUnrecordablePassphraseRollsTheFreshRingsBack() = runTest {
        // An unknown passphrase is unrecoverable, so rings the vault refuses to record must go;
        // the next login re-provisions through EnsureProvisioned.
        val harness = Harness(
            FakePgpRepository(deleteDefaultRings = { Outcome.Success(Unit) }),
            FakePasswordRepository(add = { false }),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.RecordFreshRings("ring passphrase"))

        assertIs<Outcome.Error>(outcome)
        assertEquals(2, harness.passwordRepository.added.size, "one retry before giving the rings up")
        assertEquals(1, harness.pgpRepository.deleteDefaultRingCalls)
        assertFalse(harness.pgpPreferences.isProvisionedFlagSet(userName), "so the next login retries")
        assertEquals(listOf<PgpEvent>(PgpEvent.KeyModified), harness.pgpEvents.updates)
    }

    // ------------------------------------------------------------- EnsureProvisioned (login)

    @Test
    fun aSetFlagShortCircuitsBeforeTouchingAnyRepository() = runTest {
        val harness = Harness(FakePgpRepository(), FakePasswordRepository())
        harness.pgpPreferences.presetProvisionedFlag(userName)

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
    }

    @Test
    fun existingKeysGetTheFlagAndNoNewRings() = runTest {
        // Legacy accounts keep their login-password rings; synced rings are never overwritten.
        val harness = Harness(
            FakePgpRepository(keys = { listOf(someKeyPair()) }),
            FakePasswordRepository(),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertTrue(harness.pgpRepository.createDefaultRingCalls.isEmpty())
        assertTrue(harness.passwordRepository.added.isEmpty())
        assertTrue(harness.pgpPreferences.isProvisionedFlagSet(userName))
    }

    @Test
    fun anExistingEntryGetsTheFlagAndNoNewRings() = runTest {
        val harness = Harness(
            FakePgpRepository(keys = { emptyList() }),
            FakePasswordRepository(
                entries = { listOf(existingEntry(EnsureDefaultPgpRings.entryName(userName))) },
            ),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertTrue(harness.pgpRepository.createDefaultRingCalls.isEmpty())
        assertTrue(harness.pgpPreferences.isProvisionedFlagSet(userName))
    }

    @Test
    fun aLegacyBareNameEntryAlsoSettlesTheGuard() = runTest {
        // Earlier builds wrote the bare base name, then a parenthesised profile variant.
        val harness = Harness(
            FakePgpRepository(keys = { emptyList() }),
            FakePasswordRepository(
                entries = {
                    listOf(existingEntry("${EnsureDefaultPgpRings.ENTRY_NAME} ($userName)"))
                },
            ),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertTrue(harness.pgpRepository.createDefaultRingCalls.isEmpty())
    }

    @Test
    fun aPublicOnlyKeyDoesNotBlockProvisioning() = runTest {
        // The auto-imported developer key is public-only; treating it as "this account has keys"
        // would permanently block provisioning for every account that carries it.
        val harness = Harness(
            FakePgpRepository(keys = { listOf(publicOnlyKeyPair()) }, createDefaultRings = { Outcome.Success(Unit) }),
            FakePasswordRepository(entries = { emptyList() }, add = { true }),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertEquals(true, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertEquals(1, harness.pgpRepository.createDefaultRingCalls.size)
    }

    @Test
    fun aBareAccountGetsRingsAndTheirVaultEntry() = runTest {
        val harness = Harness(
            FakePgpRepository(keys = { emptyList() }, createDefaultRings = { Outcome.Success(Unit) }),
            FakePasswordRepository(entries = { emptyList() }, add = { true }),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertEquals(true, assertIs<Outcome.Success<Boolean>>(outcome).value)
        val passphrase = harness.pgpRepository.createDefaultRingCalls.single()
        assertEquals(24, passphrase.length)
        val entry = harness.passwordRepository.added.single()
        assertEquals(EnsureDefaultPgpRings.entryName(userName), entry.entryName)
        assertEquals(passphrase, entry.password)
        assertTrue(harness.pgpPreferences.isProvisionedFlagSet(userName))
        assertEquals(listOf<PgpEvent>(PgpEvent.KeyCreated), harness.pgpEvents.updates)
    }

    @Test
    fun aFailedRingCreationWritesNothing() = runTest {
        val harness = Harness(
            FakePgpRepository(
                keys = { emptyList() },
                createDefaultRings = { Outcome.Error("keygen failed", PgpFailure.GeneralPgpError("keygen failed")) },
            ),
            FakePasswordRepository(entries = { emptyList() }),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertIs<Outcome.Error>(outcome)
        assertTrue(harness.passwordRepository.added.isEmpty())
        assertFalse(harness.pgpPreferences.isProvisionedFlagSet(userName))
        assertTrue(harness.pgpEvents.updates.isEmpty())
    }

    @Test
    fun aFailedEntryWriteRollsTheJustCreatedRingsBack() = runTest {
        val harness = Harness(
            FakePgpRepository(
                keys = { emptyList() },
                createDefaultRings = { Outcome.Success(Unit) },
                deleteDefaultRings = { Outcome.Success(Unit) },
            ),
            FakePasswordRepository(entries = { emptyList() }, add = { false }),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertIs<Outcome.Error>(outcome)
        assertEquals(1, harness.pgpRepository.deleteDefaultRingCalls)
        assertFalse(harness.pgpPreferences.isProvisionedFlagSet(userName), "so the next login retries")
    }

    @Test
    fun anOccupiedDefaultRingSlotSettlesTheAccountInsteadOfRefailingForever() = runTest {
        // A public-only ring under a default-ring name (synced alone) is invisible to the
        // secret-keys guard but blocks creation permanently — the flag must land or every login
        // re-parses and re-fails here forever.
        val harness = Harness(
            FakePgpRepository(
                keys = { emptyList() },
                createDefaultRings = { Outcome.Error("default ring files already exist", PgpFailure.DefaultRingsOccupied) },
            ),
            FakePasswordRepository(entries = { emptyList() }),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertEquals(false, assertIs<Outcome.Success<Boolean>>(outcome).value)
        assertTrue(harness.passwordRepository.added.isEmpty(), "no entry may promise rings that were not created")
        assertTrue(harness.pgpPreferences.isProvisionedFlagSet(userName), "the occupancy is permanent")
    }

    @Test
    fun anUnreadableVaultAbortsWithoutProvisioningOrFlagging() = runTest {
        // getPasswordEntries flattens an unreadable vault to an empty list; the guard uses the
        // Outcome-returning read instead, because that vault may already HOLD the entry.
        val harness = Harness(
            FakePgpRepository(keys = { emptyList() }),
            FakePasswordRepository(list = { Outcome.Error("vault unreadable", PasswordFailure.VaultUnreadable) }),
        )

        val outcome = harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned)

        assertIs<Outcome.Error>(outcome)
        assertTrue(harness.pgpRepository.createDefaultRingCalls.isEmpty())
        assertFalse(harness.pgpPreferences.isProvisionedFlagSet(userName), "a readable vault must settle it later")
    }

    @Test
    fun anAnonymousSessionIsRefusedBeforeTouchingAnything() = runTest {
        // Every repository method is unconfigured, so any touch fails the test loudly.
        val harness = Harness(
            FakePgpRepository(),
            FakePasswordRepository(),
            userPreferences = FakeLoggedInUserPreferences(AppUser.Anonymous),
        )

        assertIs<Outcome.Error>(harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned))
        assertFalse(harness.pgpPreferences.isProvisionedFlagSet(userName))
    }

    @Test
    fun aCancellationDuringKeygenStillCommitsTheWholeSequence() = runTest {
        // The caller's timeout must only ever bound the guard phase. A cancellation delivered
        // while the (blocking, real-world) 4096-bit keygen runs lands AFTER the rings are on
        // disk; tearing the sequence apart there would orphan rings whose passphrase nobody
        // recorded — and the next login's secret-keys guard would then flag the account, making
        // the orphan permanent.
        val createEntered = CompletableDeferred<Unit>()
        val releaseCreate = CompletableDeferred<Unit>()
        val harness = Harness(
            FakePgpRepository(
                keys = { emptyList() },
                createDefaultRings = {
                    createEntered.complete(Unit)
                    releaseCreate.await() // the "keygen" runs while the caller cancels
                    Outcome.Success(Unit)
                },
            ),
            FakePasswordRepository(entries = { emptyList() }, add = { true }),
        )

        val job = launch { harness.useCase(EnsureDefaultPgpRings.Request.EnsureProvisioned) }
        createEntered.await()
        job.cancel()
        releaseCreate.complete(Unit)
        job.join()

        assertEquals(1, harness.passwordRepository.added.size, "the passphrase must still be recorded")
        assertTrue(harness.pgpPreferences.isProvisionedFlagSet(userName), "the flag must still be set")
        assertEquals(0, harness.pgpRepository.deleteDefaultRingCalls, "nothing rolled back — the sequence completed")
    }
}

package ai.passman.platform.repository

import ai.passman.cache.di.passmanSessionScope
import ai.passman.crypto.CryptoKey
import ai.passman.crypto.vault.VaultCipher
import ai.passman.crypto.vault.VaultSession
import ai.passman.crypto.vault.VaultSessionKey
import ai.passman.domain.connectivity.model.TrustedDevice
import ai.passman.platform.storage.PasswordDatabaseStorage
import ai.passman.platform.transfer.PasswordTransferService
import ai.passman.platform.vault.PortableVaultFormat
import ai.passman.repo.di.PRIVATE_DECRYPTION_KEY_HANDLE
import ai.passman.repo.di.VAULT_SESSION_HANDLE
import ai.passman.logging.KLogger
import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.base.model.Outcome
import ai.passman.domain.password.AddPassword
import ai.passman.domain.password.exception.PasswordFailure
import ai.passman.domain.password.model.EntryActivity
import ai.passman.domain.password.model.PasswordEntry
import ai.passman.domain.password.repository.PasswordRepository
import ai.passman.domain.settings.exception.TransferFailure
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import kotlin.time.Clock
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.withContext
import kotlinx.serialization.json.Json
import org.koin.core.qualifier.named
import org.koin.core.scope.Scope

/**
 * How many times a mutation re-reads the vault and re-applies itself after losing the conditional
 * publish.
 *
 * Bounded rather than unbounded because the loop's exit condition is another process standing still,
 * which is not something this side controls. Three is chosen against the shape of the contention this
 * guards: real losses come from a *migration* or a renumber-on-read racing a save, and both of those
 * are one-shot — after the first round the vault is suite 5 and settled, so the second attempt is
 * almost always uncontended. A run that loses three times in a row is not contention, it is a writer
 * that never stops, and looping longer would only postpone telling the caller.
 */
private const val PUBLISH_ATTEMPTS = 3

/**
 * The vault's read/write path, and the migration that takes an RSA-wrapped vault to suite 5.
 *
 * ## What migration must never cost
 *
 * The vault is the product. Every ordering decision below is made so that a failure — any failure —
 * leaves the file that was there before, byte for byte, and leaves the account able to open it:
 *
 * 1. **A vault that did not read is never written over.** This predates the keyring (it is the C5
 *    regression guard) and it is what turns every other bug in this file from "your entries are
 *    gone" into "the app showed nothing this time". It is load-bearing for migration too, because
 *    the migration read is the one most likely to fail on a real machine: a `.pfx` restored from a
 *    different account, a half-copied data directory, a `keystore/` that came back from backup while
 *    `database/` did not.
 * 2. **Nothing is sealed and published in one motion.** [sealAndVerify] encrypts and then *decrypts
 *    the very bytes it is about to write* and compares them to the plaintext they were built from.
 *    "It wrote successfully" is not the property that matters; "it opens again" is, and the only
 *    moment it can be established without risk is before the old bytes are gone.
 * 3. **A legacy vault is never converted without its downgrade copy.** `<db>.premigration.v2` is
 *    written first, and a failure to write it aborts the conversion. Refusing to convert costs the
 *    user nothing; converting without it costs them the only thing an older build can read.
 * 4. **Every publish is conditional, and a save that loses is re-applied rather than dropped.** A
 *    read-modify-write here spans a decrypt, a re-encrypt and two disk round trips, and another one
 *    can land inside it. Publishing unconditionally overwrites the winner with the entry list this
 *    caller read beforehand, so *every* write from this class — the pure migration in [migrateVault]
 *    and the ordinary saves in [writeEntries] alike — goes through
 *    [PasswordDatabaseStorage.replaceIfUnchanged] against the ciphertext it read.
 *
 *    Making only the migration conditional was not enough: the branch a real legacy vault takes on
 *    the first session after an update is the *renumbering* one, which is a save, and that is
 *    precisely the session in which the user is most likely to be typing.
 *
 *    But a conditional write on its own only moves the loss to the other writer, so a superseded
 *    mutation does not stand down — [mutateVault] re-reads the newer vault and applies the same
 *    change to it. Only the pure migration stands down on a lost race, because there is by then
 *    nothing left to re-apply: whoever won wrote suite 5.
 *
 * ## Where the RSA identity still appears
 *
 * Only as [legacyPrivateKey], only inside a lambda, and only for envelopes that are not suite 5.
 * That laziness is the whole reason [VaultCipher.decryptVault] takes a provider: a migrated account
 * must never open its PKCS#12 identity store to read its own vault, and the tests assert exactly
 * that by removing the RSA handles from the scope entirely.
 *
 * ## Why every mutation names its target by uuid
 *
 * [PasswordEntry.id] is a display ordinal that this class itself reassigns on every read and every
 * merge, so it cannot address a row across the gap between reading the vault and publishing to it.
 * A retry makes that gap explicit: point 4 above re-applies a superseded mutation to the vault that
 * won, and the vault that won may have renumbered. An `id` captured before the loop then names a
 * *different* entry on the second attempt — a delete that destroys an unrelated credential while
 * leaving the requested one in place, and reports success for both halves of that.
 *
 * So the mutation lambdas below resolve their target out of the entry list they are handed, by
 * [PasswordEntry.uuid], on every attempt. A target that is no longer there returns null, which
 * [mutateVault] reads as "nothing to do" — never as licence to act on whatever now occupies the
 * ordinal.
 *
 * ## Why every mutation acts on at most one row
 *
 * The uuid is *meant* to be unique, and for entries created after it existed it is. Derived
 * identities cannot promise it: two rows sharing both a name and a username hash to one uuid, and
 * there is no third field two devices are guaranteed to agree on (see [PasswordEntryIdentity]). A
 * mutation written as `filterNot { it.uuid == target }` or `map { if (it.uuid == target) ... }` then
 * acts on *every* row that matches, which turns "delete this login" into "delete both logins for
 * this site" — a strictly worse outcome than the ambiguity itself.
 *
 * So the lambdas resolve an *index* and rewrite or drop that one position. Which of two
 * indistinguishable rows is chosen is arbitrary, but it is the same choice `GetPassword` makes when
 * it looks one up, and one row surviving is recoverable where none surviving is not.
 *
 * ## A deleted row stays in the vault
 *
 * A delete stamps the row with an [EntryActivity.KIND_DELETED] record instead of removing it (see
 * [tombstoned]). It has to: a dropped row leaves a vault byte-indistinguishable from one the entry
 * never existed in, and both merge sites are a union keyed on uuid with no arm that can *remove* one,
 * so the next sync with a peer that still holds the row reads it as new and adds it straight back.
 *
 * The consequence for everything else in this class is that the entry list it works on is not the
 * entry list its callers see. [parseEntries] and every mutation lambda deal in the stored rows,
 * tombstones included — that is what keeps a deletion alive across a save. Only the two read methods
 * ([getPasswordEntries], [listPasswordEntries]) filter, and they filter on the way *out*, after the
 * write. Filtering earlier would be the same bug in a new place: a mutation that re-published a list
 * with the tombstones already dropped would resurrect every entry the user had ever deleted.
 */
class LocalPasswordRepository(
    private val userPreferences: UserPreferences,
    private val coroutinesContextFacade: CoroutinesContextFacade,
    private val vaultCipher: VaultCipher,
    private val storage: PasswordDatabaseStorage,
    private val transferService: PasswordTransferService,
    private val entryIdentity: PasswordEntryIdentity,
    private val portableVaultFormat: PortableVaultFormat? = null,
) : PasswordRepository {

    override suspend fun addPasswordEntry(entry: AddPassword.EntryData): Boolean =
        withContext(coroutinesContextFacade.io) {
            KLogger.d { "addPasswordEntry ${entry.entryName}" }
            passmanSessionScope(userPreferences.getSessionId()) { scope ->
                val user = userPreferences.getUser() as AppUser.LoggedIn
                // Drawn once, outside the retry: "assigned once, never reused" is the whole contract of
                // the field, and a retry is the same entry being saved again rather than a second one.
                val uuid = entryIdentity.newUuid()
                mutateVault(scope, user.userName, "addPasswordEntry") { current ->
                    val entries = current.toMutableList()
                    // `toIntOrNull`, not `toInt`: nothing validates the ordinal on the way into the
                    // vault (a sync can carry anything), and this lambda runs outside every
                    // runCatching — a bad ordinal must cost nothing, not fail the add.
                    val currentIndex = entries.maxOfOrNull { it.id.toIntOrNull() ?: 0 } ?: 0
                    // One timestamp for dateCreated, createdAt and the sole activity record: the merge
                    // rule that keeps the newest activity `at` equal to `dateCreated` (see
                    // updatePasswordEntry) starts being true from the very first write, not from the
                    // first edit.
                    val now = Clock.System.now().toEpochMilliseconds()
                    entries.add(
                        PasswordEntry(
                            uuid = uuid,
                            id = (currentIndex + 1).toString(),
                            dateCreated = now,
                            entryName = entry.entryName,
                            password = entry.password,
                            website = entry.website,
                            username = entry.userName,
                            notes = entry.notes,
                            totpSeed = entry.totpSeed,
                            customFields = entry.customFields,
                            createdAt = now,
                            activity = listOf(EntryActivity(now, EntryActivity.KIND_CREATED)),
                        ),
                    )
                    // Numeric, not lexicographic: as strings, ordinal 10 files between 1 and 2. The
                    // stray non-numeric ordinal sorts last rather than crashing the save.
                    entries.sortedBy { it.id.toIntOrNull() ?: Int.MAX_VALUE }
                }
            } ?: false
        }

    override suspend fun getPasswordEntries(): List<PasswordEntry> = withContext(coroutinesContextFacade.io) {
        KLogger.d { "getPasswordEntries" }
        passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val user = userPreferences.getUser() as AppUser.LoggedIn
            var latest = emptyList<PasswordEntry>()
            repeat(PUBLISH_ATTEMPTS) { attempt ->
                // The local DB could not be read (bad key, corruption, tampering).
                // NEVER overwrite it — that would destroy the only local copy and,
                // with no MAC, let a single flipped ciphertext byte wipe the vault.
                // Surface an empty list for display but leave the ciphertext intact
                // so it can be recovered (correct key, restore from `.bak`, or re-sync).
                val vault = openVault(scope, user.userName, "getPasswordEntries")
                    ?: return@passmanSessionScope emptyList()
                val entries = parseEntries(vault, "getPasswordEntries")
                    ?: return@passmanSessionScope emptyList()

                if (entries.isEmpty()) {
                    KLogger.d { "empty list" }
                    // An empty legacy vault is still a legacy vault, and it is the cheapest one to
                    // convert. Skipping it here would leave accounts stuck on RSA wrapping forever.
                    migrateVault(scope, user.userName, vault)
                    return@passmanSessionScope emptyList()
                }

                // The one path that is guaranteed to run and to write, so it is where a tombstone
                // that has outlived its window is actually reaped — dropping it in `parseEntries`
                // instead would hide the row from this list while leaving it on disk forever,
                // because the comparison below would then never see a difference to publish.
                val unexpired = entries.withoutExpiredTombstones(Clock.System.now().toEpochMilliseconds())
                val sorted = unexpired.sortedBy { it.entryName.lowercase() }
                val renumbered = sorted.withDisplayOrdinals()
                // What the caller gets when the renumbering does not reach the disk: display order,
                // but the ordinals that are actually stored. Handing back numbers no vault holds
                // would only be safe while nothing addresses an entry by them, and the whole reason
                // this class moved to uuids is that something did.
                latest = sorted.live()
                // Persist the renumbering only when it actually changed, so a plain
                // read isn't a write. Storage writes are atomic (see JvmPasswordDatabaseStorage),
                // so this can no longer truncate the vault on a crash. Compared against the list as
                // parsed, tombstones included: an expiry that removed a row is a change worth
                // publishing even when nothing was renumbered.
                if (renumbered == entries) {
                    migrateVault(scope, user.userName, vault)
                    return@passmanSessionScope renumbered.live()
                }
                // The tombstoned rows go to disk and only the live ones come back to the caller.
                when (writeEntries(scope, user.userName, renumbered, vault)) {
                    Publish.Published -> return@passmanSessionScope renumbered.live()
                    Publish.Failed -> return@passmanSessionScope sorted.live()
                    // Somebody published between this read and this write, so the list just
                    // renumbered is already stale. Read the newer vault and renumber that instead —
                    // returning the stale list would show the user entries that no longer exist.
                    Publish.Superseded -> KLogger.w {
                        "getPasswordEntries: the vault changed underneath the renumbering - " +
                            "re-reading it (attempt ${attempt + 1})"
                    }
                }
            }
            latest
        } ?: emptyList()
    }

    /**
     * The error-aware read. A pure read on purpose: unlike [getPasswordEntries] it never renumbers,
     * migrates or writes anything, and an unreadable vault comes back as
     * [PasswordFailure.VaultUnreadable] instead of the display path's empty list — a caller that
     * acts on "the vault does not contain X" must not act on an answer that might merely mean
     * "could not look".
     *
     * Tombstoned rows are filtered out here too, so a deleted entry reads as absent rather than as
     * a row nobody can see. Being a pure read it does not reap expired tombstones — it only hides
     * them, which is the same answer.
     */
    override suspend fun listPasswordEntries(): Outcome<List<PasswordEntry>> = withContext(coroutinesContextFacade.io) {
        passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val user = userPreferences.getUser() as? AppUser.LoggedIn
                ?: return@passmanSessionScope Outcome.Error("not signed in", PasswordFailure.VaultUnreadable)
            val vault = openVault(scope, user.userName, "listPasswordEntries")
                ?: return@passmanSessionScope Outcome.Error("vault unreadable", PasswordFailure.VaultUnreadable)
            val entries = parseEntries(vault, "listPasswordEntries")
                ?: return@passmanSessionScope Outcome.Error("vault undecodable", PasswordFailure.VaultUnreadable)
            Outcome.Success(entries.live().sortedBy { it.entryName.lowercase() })
        } ?: Outcome.Error("no session", PasswordFailure.VaultUnreadable)
    }

    override suspend fun updatePasswordEntry(entry: PasswordEntry): Boolean = withContext(coroutinesContextFacade.io) {
        KLogger.d { "updatePasswordEntry, entry: ${entry.uuid}" }
        passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val user = userPreferences.getUser() as AppUser.LoggedIn
            mutateVault(scope, user.userName, "updatePasswordEntry") { current ->
                // An index, not a predicate over the whole list: two rows can share a derived uuid,
                // and rewriting both would overwrite a credential the user never opened.
                //
                // A tombstoned row is not a target. It is still physically in the vault (that is what
                // makes the deletion stick across a sync), so without this the edit would rewrite it
                // — and while `mergeActivity` would carry the deletion record along and keep the row
                // hidden, the write would have overwritten a deleted credential's fields for nothing
                // and reported success for an edit the user cannot see.
                val target = current.indexOfFirst { it.uuid == entry.uuid && !it.isTombstoned }
                if (target < 0) {
                    // Deleted by another device, or by this one between the read and the save. Not a
                    // reason to write anything: the alternative is re-adding an entry the user
                    // removed, or editing whichever row inherited its ordinal.
                    KLogger.w { "updatePasswordEntry: ${entry.uuid} is not in the vault - nothing to update" }
                    return@mutateVault null
                }
                current.mapIndexed { position, existing ->
                    if (position != target) {
                        existing
                    } else {
                        // The ordinal comes from the vault, not from the caller: `entry` was read
                        // before this attempt and may be carrying a number the vault has since
                        // handed to somebody else. `createdAt` and `activity` join that list for the
                        // same reason: a caller that read the entry before another device's merge
                        // landed would otherwise roll the history back to whatever it had on hand,
                        // discarding activity records a sync already delivered to this vault.
                        val now = Clock.System.now().toEpochMilliseconds()
                        entry.copy(
                            uuid = existing.uuid,
                            id = existing.id,
                            dateCreated = now,
                            createdAt = existing.createdAt,
                            // The new record's `at` is this same `now`, so this edit path guarantees the
                            // newest activity entry equals `dateCreated` immediately after *this* write —
                            // not a vault-wide invariant: a merged-in peer record can carry a
                            // skewed-future `at` that outranks it later. mergeActivity also caps at
                            // MAX_ACTIVITY, which is what bounds this append the same way it bounds a
                            // merge's union.
                            activity = mergeActivity(existing.activity, listOf(EntryActivity(now, EntryActivity.KIND_EDITED))),
                        )
                    }
                }
            }
        } ?: false
    }

    override suspend fun deletePasswordEntry(passwordUuid: String): Boolean = withContext(coroutinesContextFacade.io) {
        KLogger.d { "deletePasswordEntry, entry: $passwordUuid" }
        passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val user = userPreferences.getUser() as AppUser.LoggedIn
            mutateVault(scope, user.userName, "deletePasswordEntry") { current ->
                // One row, by index. `filterNot { it.uuid == passwordUuid }` would remove every row
                // sharing the uuid, so a user deleting one of their two logins for a site would lose
                // both — the failure mode this whole field exists to remove, in a louder form.
                //
                // Already-tombstoned rows are skipped rather than matched, for the same reason: when
                // two rows share a derived identity and one of them is already deleted, the delete
                // has to land on the one that is still alive.
                val target = current.indexOfFirst { it.uuid == passwordUuid && !it.isTombstoned }
                if (target < 0) {
                    // Already gone. Publishing an identical list would report a delete that did not
                    // happen, and the ordinal that used to name it now names something else.
                    KLogger.w { "deletePasswordEntry: $passwordUuid is not in the vault - nothing to delete" }
                    return@mutateVault null
                }
                // Stamped, not dropped. A dropped row leaves a vault byte-indistinguishable from one
                // the entry never existed in, so the next merge with a peer that still holds it reads
                // the row as new and adds it straight back — see [tombstoned].
                val now = Clock.System.now().toEpochMilliseconds()
                current.mapIndexed { position, existing ->
                    if (position == target) existing.tombstoned(now) else existing
                }
            }
        } ?: false
    }

    // Single read + write so the entire set is deleted atomically. Avoids a race
    // where consumers of `getPasswordEntries()` would renumber IDs between
    // sequential single-deletes and the next iteration would no longer match.
    override suspend fun deletePasswordEntries(passwordUuids: Collection<String>): Int =
        withContext(coroutinesContextFacade.io) {
            KLogger.d { "deletePasswordEntries, count: ${passwordUuids.size}" }
            if (passwordUuids.isEmpty()) return@withContext 0
            passmanSessionScope(userPreferences.getSessionId()) { scope ->
                val user = userPreferences.getUser() as AppUser.LoggedIn
                // Recomputed on every attempt, because a retry applies the delete to a *different*
                // entry list: reporting the first attempt's count for the second attempt's write
                // would tell the caller entries were removed that another writer had already taken.
                var removed = 0
                val published = mutateVault(scope, user.userName, "deletePasswordEntries") { current ->
                    // The target set is consumed as it matches, so each uuid takes out one row and no
                    // more. That keeps a shared derived identity from turning a selection of one into
                    // a delete of two, and it is what makes the returned count comparable to the
                    // number of uuids the caller selected — the confirmation dialog counts the
                    // selection, and a count larger than it would be a lie about what was deleted.
                    // Built inside the lambda because a retry has to start from the full set again.
                    val unmatched = passwordUuids.toHashSet()
                    val now = Clock.System.now().toEpochMilliseconds()
                    // Counted as the rows are stamped, not as `current.size - kept.size`: nothing is
                    // removed any more, so a size difference would always be zero and every batch
                    // delete would report that it deleted nothing.
                    var stamped = 0
                    val next = current.map { row ->
                        // `!isTombstoned` first, so a uuid is never consumed by a row that was
                        // already deleted while its live namesake goes untouched.
                        if (!row.isTombstoned && unmatched.remove(row.uuid)) {
                            stamped++
                            row.tombstoned(now)
                        } else {
                            row
                        }
                    }
                    removed = stamped
                    if (removed == 0) {
                        // None of them are there any more. There is nothing to publish, and the
                        // count the caller gets has to say so.
                        KLogger.w { "deletePasswordEntries: none of the targets are in the vault" }
                        return@mutateVault null
                    }
                    next
                }
                // Nothing published means nothing deleted, and reporting a count for a delete that
                // never landed would tell the caller its entries are gone when they are still there.
                if (published) removed else 0
            } ?: 0
        }

    override suspend fun transferPasswordDatabase(hostName: String): Outcome<Unit> {
        return try {
            passmanSessionScope(userPreferences.getSessionId()) { scope ->
                val user = userPreferences.getUser() as AppUser.LoggedIn
                // A read, and only a read: a transfer is not the moment to rewrite the vault, and
                // failing the transfer because a migration failed would be the wrong trade.
                val vault = openVault(scope, user.userName, "transferPasswordDatabase")
                    ?: return@passmanSessionScope Outcome.Error(
                        "failed to read password database",
                        TransferFailure.GeneralTransferFailure,
                    )

                transferService.transferDatabaseBytes(
                    decryptedDatabaseBytes = vault.plaintext,
                    fileName = "${user.userName.hashCode()}",
                    hostName = hostName,
                )
            } ?: Outcome.Error("Failed to create scope", TransferFailure.GeneralTransferFailure)
        } catch (error: Throwable) {
            if (error is CancellationException) throw error
            KLogger.e(error) { "transferPasswordDatabase failed" }
            Outcome.Error("failed to transfer password database", TransferFailure.GeneralTransferFailure)
        }
    }

    /**
     * The sync-session push, against the record the chooser handed us rather than its address.
     *
     * Deliberately not routed through [transferPasswordDatabase]: that one exists for the address a
     * user types into Settings > Transfer and has to resolve it to a pairing, which is a lookup over
     * a field two pairings can share. A session already knows which device it is talking to, so it
     * hands the record straight to the transport and the SPKI that gets pinned is always the one the
     * user picked.
     */
    override suspend fun pushPasswordDatabase(device: TrustedDevice): Outcome<Unit> {
        return try {
            passmanSessionScope(userPreferences.getSessionId()) { scope ->
                val user = userPreferences.getUser() as AppUser.LoggedIn
                // A read, and only a read: a transfer is not the moment to rewrite the vault, and
                // failing the transfer because a migration failed would be the wrong trade.
                val vault = openVault(scope, user.userName, "pushPasswordDatabase")
                    ?: return@passmanSessionScope Outcome.Error(
                        "failed to read password database",
                        TransferFailure.GeneralTransferFailure,
                    )

                transferService.transferDatabaseBytes(
                    decryptedDatabaseBytes = vault.plaintext,
                    fileName = "${user.userName.hashCode()}",
                    device = device,
                )
            } ?: Outcome.Error("Failed to create scope", TransferFailure.GeneralTransferFailure)
        } catch (error: Throwable) {
            if (error is CancellationException) throw error
            KLogger.e(error) { "pushPasswordDatabase failed" }
            Outcome.Error("failed to transfer password database", TransferFailure.GeneralTransferFailure)
        }
    }

    override suspend fun pullPasswordDatabase(device: TrustedDevice): Outcome<Unit> {
        return passmanSessionScope(userPreferences.getSessionId()) { scope ->
            val user = userPreferences.getUser() as AppUser.LoggedIn

            when (val pullOutcome = transferService.pullDatabase(device = device)) {
                is Outcome.Error -> pullOutcome
                is Outcome.Success -> {
                    // The transfer service already decrypted the (post-quantum) response. What lands
                    // locally is sealed under the *local* session key as suite 5 — never re-sealed
                    // under RSA, which would drag a migrated vault back onto the wrapping this
                    // change exists to remove.
                    val peerBytes = pullOutcome.value
                    if (peerBytes.isEmpty()) {
                        return@passmanSessionScope Outcome.Success(Unit)
                    }
                    val mergeResult = runCatching {
                        val peerJson = peerBytes.decodeToString()
                        if (peerJson.isNotEmpty()) {
                            // VaultJson, not the strict default: an upgraded peer's extra field is
                            // the one thing a strict decode rejects that a lenient one should not.
                            val peerEntries = VaultJson.decodeFromString<List<PasswordEntry>>(peerJson)
                            // The merge is a function of whatever the vault currently holds, so it
                            // replays cleanly onto a vault that changed mid-pull. A pull that could
                            // not publish is reported as an error rather than as a quiet success:
                            // the peer's entries are not in the vault, and the caller is the one that
                            // decides whether to try again.
                            val published = mutateVault(scope, user.userName, "pullPasswordDatabase") { existing ->
                                mergePasswordEntries(existing = existing, incoming = peerEntries)
                            }
                            check(published) { "the local vault could not be merged with the sync pull" }
                        }
                    }.onFailure {
                        if (it is CancellationException) throw it
                        KLogger.e(it) { "sync pull merge failed" }
                    }
                    if (mergeResult.isFailure) {
                        Outcome.Error("failed to merge password sync pull", TransferFailure.GeneralTransferFailure)
                    } else {
                        Outcome.Success(Unit)
                    }
                }
            }
        } ?: Outcome.Error("Failed to create scope", TransferFailure.GeneralTransferFailure)
    }

    /**
     * Two entry lists reduced to one, keyed on [PasswordEntry.uuid].
     *
     * This used to key on [PasswordEntry.entryName], which made the name the de facto primary key of
     * the whole sync protocol and lost data in both directions: two entries sharing a name collapsed
     * into one, and renaming an entry on one device produced a duplicate of it on the next merge,
     * because the new name was a new key.
     *
     * **The first merge after the upgrade is unchanged wherever names are unique.** Every entry that
     * predates the uuid field derives one from `entryName | 0x00 | username`, so on two migrated
     * vaults `uuid` is a relabelling of the name and this produces the same grouping, in the same
     * order, as the name-keyed version did. It diverges in exactly two places, both of them the point
     * of the change: entries created afterwards carry uuids that were never a function of their name
     * and so survive a rename, and two pre-existing entries that shared a name but not a username now
     * both survive instead of one silently replacing the other.
     *
     * [incoming] is stabilised here rather than at the call sites because it can arrive from a peer
     * that has not upgraded, in which case its rows have no uuid at all; deriving it on this side
     * reaches the same values the peer would have, which is the property the whole scheme rests on.
     * The conflict rule itself is untouched: newer [PasswordEntry.dateCreated] wins.
     *
     * ## Everything that has to apply "whichever copy wins" lives in [mergeEntry]
     *
     * The tombstone check, the `activity` union and the `createdAt` minimum all have to run
     * regardless of which of the two copies survives the `dateCreated` comparison. Written inline
     * that used to mean four arms across two merge sites, three of which do nothing by default: a
     * rule added to only the winning arm applies only when the incoming row happens to be newer, and
     * the two vaults then never converge — the mirror merge on the peer unions in the *other*
     * direction, history flip-flops between syncs instead of settling, and [minNonZero] is
     * unreachable in exactly the cases it exists for. [mergeEntry] is the whole pairwise decision in
     * one place so there are no arms left to forget; only `current == null` stays here, because there
     * is no pair to reduce.
     *
     * ## A uuid that arrives only as a tombstone is kept as one
     *
     * `current == null` takes the incoming row as-is, tombstone included. This device may have no
     * copy of the entry at all — but a *third* device might, and dropping the tombstone here would
     * make this vault the thing that hands the entry back to it.
     */
    private fun mergePasswordEntries(
        existing: List<PasswordEntry>,
        incoming: List<PasswordEntry>,
    ): List<PasswordEntry> {
        val byUuid = entryIdentity.stabilize(existing).associateBy { it.uuid }.toMutableMap()
        for (entry in entryIdentity.stabilize(incoming)) {
            val current = byUuid[entry.uuid]
            byUuid[entry.uuid] = if (current == null) entry else mergeEntry(current, entry)
        }
        // Expiry is applied to the merged result, not to `existing` on the way in: a tombstone this
        // side has already reaped can arrive again on the peer's row, and the deadline has to be
        // enforced against what is about to be written rather than against what was read.
        return byUuid.values.toList()
            .withoutExpiredTombstones(Clock.System.now().toEpochMilliseconds())
            .sortedBy { it.entryName.lowercase() }
            .withDisplayOrdinals()
    }

    /**
     * What was on disk and what it decrypted to.
     *
     * The ciphertext is carried alongside the plaintext because both later steps need it: the
     * downgrade copy is made *of these exact bytes*, and the conditional rewrite is conditional on
     * the vault still being them.
     */
    private class OpenVault(
        val plaintext: ByteArray,
        val ciphertext: ByteArray,
        val needsMigration: Boolean,
    )

    /** The decrypted vault, or null with the reason logged — callers must then write nothing. */
    private fun openVault(scope: Scope, username: String, caller: String): OpenVault? = runCatching {
        val sessionKey = sessionKey(scope)
        val ciphertext = storage.read(username)
        if (portableVaultFormat?.isPortable(ciphertext) == true) {
            OpenVault(portableVaultFormat.open(username, ciphertext, sessionKey), ciphertext, needsMigration = false)
        } else {
            val unlocked = vaultCipher.decryptVault(ciphertext, sessionKey) { legacyPrivateKey(scope) }
            // In production the portable binding is always present, so even suite 5 moves once.
            // The null fallback keeps the pre-existing JVM-only repository fixtures on their PMNV
            // contract; iOS intentionally has no local-vault binding.
            OpenVault(
                unlocked.plaintext,
                ciphertext,
                // Suite 2/3 material still needs the existing migration even in the test/iOS
                // fallback. When the portable binding is installed, a suite-5 PMNV vault also
                // moves exactly once into the portable CMS envelope.
                needsMigration = unlocked.needsMigration || portableVaultFormat != null,
            )
        }
    }.getOrElse {
        if (it is CancellationException) throw it
        KLogger.e(it) {
            "$caller: failed to read local DB - preserving ciphertext, showing empty. " +
                "(cause: ${it::class.simpleName})"
        }
        null
    }

    /**
     * The entries in [vault], or null when the plaintext is not a vault.
     *
     * An empty plaintext is a genuinely empty vault. A NON-empty plaintext that fails to parse means
     * the data is corrupt or tampered — report it as unreadable so callers abort instead of silently
     * treating it as empty and overwriting the real vault with the result.
     *
     * This is also the single point at which a vault written before uuids existed acquires them. It
     * is a *derivation*, not a conversion: it is deterministic, it costs one SHA-256 per row, and it
     * needs nothing written back, so a legacy vault that is only ever read keeps producing the same
     * identities forever and one that is written for some other reason simply carries them along.
     * Doing it here rather than at each call site is what stops a mutation from resolving a uuid
     * against rows that have none.
     *
     * It deliberately does **not** hide tombstoned rows. Every mutation is a read-modify-write over
     * whatever this returns, so a filter here would mean the next save republished the vault with
     * every deleted row silently gone — and a peer that still held one would hand it back on the
     * following sync. Hiding is the two read methods' job, on the way out.
     */
    private fun parseEntries(vault: OpenVault, caller: String): List<PasswordEntry>? {
        val jsonString = vault.plaintext.decodeToString()
        if (jsonString.isEmpty()) return emptyList()
        return runCatching { entryIdentity.stabilize(VaultJson.decodeFromString<List<PasswordEntry>>(jsonString)) }
            .getOrElse {
                KLogger.e(it) { "$caller: password DB failed to parse - preserving ciphertext" }
                null
            }
    }

    /**
     * What happened to a publish. The three cases exist because they need three different responses:
     * [Published] is done, [Superseded] is worth trying again against the newer vault, and [Failed] is
     * not — a retry would only repeat the same exception.
     */
    private enum class Publish { Published, Superseded, Failed }

    /**
     * Read the vault, apply [mutate] to its entries, publish the result — and start the whole round
     * trip over when somebody else published first.
     *
     * Re-reading rather than standing down is the point. A conditional publish on its own does not
     * remove the data loss it was added for, it only chooses a different victim: the loser's own edit
     * vanishes instead of the winner's, which from the user's side is the same bug wearing the other
     * hat. Re-applying [mutate] to the entry list that actually won keeps both.
     *
     * That is why every mutation is expressed as a *function of the current entries* rather than as a
     * precomputed list. A list computed against the old vault cannot be replayed against the new one;
     * "add this entry", "remove this uuid" and "merge these in" can.
     *
     * The same applies to the *target* of a mutation, and it is the sharper half of the rule. [mutate]
     * must resolve which entry it is acting on out of the list it is handed, every time it runs. A
     * target captured before the loop is a target named against a vault that is one attempt out of
     * date, and since a losing attempt is usually lost to a renumbering read, the captured
     * [PasswordEntry.id] is precisely the thing most likely to have moved. Resolving by
     * [PasswordEntry.uuid] inside the lambda is what makes the second attempt act on the entry the
     * caller chose rather than on the entry that inherited its number.
     *
     * [mutate] returns null for "there is nothing to do", which is not a failure and is not retried.
     * A vault that cannot be read or parsed stops immediately — writing over it is the one thing this
     * class must never do.
     *
     * @return true when a mutated vault was published.
     */
    private fun mutateVault(
        scope: Scope,
        username: String,
        caller: String,
        mutate: (List<PasswordEntry>) -> List<PasswordEntry>?,
    ): Boolean {
        repeat(PUBLISH_ATTEMPTS) { attempt ->
            // Never write on top of a vault we couldn't read — that would drop every existing entry.
            // Abort the mutation and keep the ciphertext.
            val vault = openVault(scope, username, caller) ?: return false
            val entries = parseEntries(vault, caller) ?: return false
            val mutated = mutate(entries) ?: return false
            when (writeEntries(scope, username, mutated, vault)) {
                Publish.Published -> return true
                Publish.Failed -> return false
                Publish.Superseded -> KLogger.w {
                    "$caller: the vault changed underneath this save - applying it to the newer copy " +
                        "instead (attempt ${attempt + 1})"
                }
            }
        }
        KLogger.e { "$caller: gave up after $PUBLISH_ATTEMPTS attempts - nothing was saved" }
        return false
    }

    /**
     * Seal [entries] and publish them, converting a legacy vault on the way.
     *
     * [previous] is what this write is replacing, and it is used twice. When it was a legacy envelope
     * the downgrade copy is made first and a failure there aborts the write, because a converted vault
     * with no downgrade copy is the one state the compatibility policy does not allow. And its
     * *ciphertext* is what the publish is conditional on: this method is reached by way of a decrypt,
     * a mutation and a re-encrypt, and if the vault changed in between then [entries] was computed
     * from bytes that are no longer the truth. Publishing it anyway is how the entry somebody else
     * just saved disappears.
     *
     * A [Publish.Superseded] result is not an error and is not the end of the save — [mutateVault]
     * turns it into another attempt against the vault that won.
     */
    private fun writeEntries(
        scope: Scope,
        username: String,
        entries: List<PasswordEntry>,
        previous: OpenVault,
    ): Publish = runCatching {
        val sessionKey = sessionKey(scope)
        if (previous.needsMigration) retainDowngradeCopy(username, previous)
        val sealed = sealAndVerify(username, VaultJson.encodeToString(entries).encodeToByteArray(), sessionKey)
        if (storage.replaceIfUnchanged(username, previous.ciphertext, sealed)) {
            Publish.Published
        } else {
            Publish.Superseded
        }
    }.getOrElse {
        if (it is CancellationException) throw it
        KLogger.e(it) { "failed to save the vault - the previous ciphertext is untouched" }
        Publish.Failed
    }

    /**
     * Rewrite a legacy vault as suite 5 without changing a single entry.
     *
     * Split from [writeEntries] because it is the one write whose plaintext is *already* on disk
     * under another wrapping, which makes two extra safeguards affordable here and nowhere else: the
     * publish is conditional on the vault being unchanged, and a failed read-back rolls it straight
     * back to the legacy bytes — a rollback that cannot lose anything, since the entries on both
     * sides of it are identical.
     */
    private fun migrateVault(scope: Scope, username: String, vault: OpenVault) {
        if (!vault.needsMigration) return
        runCatching {
            val sessionKey = sessionKey(scope)
            retainDowngradeCopy(username, vault)
            val sealed = sealAndVerify(username, vault.plaintext, sessionKey)
            if (!storage.replaceIfUnchanged(username, vault.ciphertext, sealed)) {
                KLogger.w { "vault migration: the vault changed while migrating - leaving the newer copy alone" }
                return@runCatching
            }
            val readBack = runCatching {
                portableVaultFormat?.open(username, storage.read(username), sessionKey)
                    ?: vaultCipher.decryptVault(storage.read(username), sessionKey) { null }.plaintext
            }.getOrNull()
            if (readBack == null || !readBack.contentEquals(vault.plaintext)) {
                KLogger.e { "vault migration: the migrated vault did not read back - restoring the original" }
                // Conditional on the bad bytes still being there, so a save that landed in the gap
                // wins over the rollback rather than being undone by it.
                //
                // Note what this costs: `replaceIfUnchanged` delegates to `write`, which refreshes
                // `.bak` from the *current* target first — so after a rollback the backup generation
                // holds the sealed bytes that did not read back, not the legacy vault. That is
                // acceptable only because the legacy vault is restored to the target and is also
                // retained as `.premigration.v2`; it has two homes, and `.bak` was never one of them.
                storage.replaceIfUnchanged(username, sealed, vault.ciphertext)
                return@runCatching
            }
            KLogger.i { "vault migration: rewrote the vault as suite 5" }
        }.onFailure {
            if (it is CancellationException) throw it
            // Nothing was published, or the publish was rolled back. The account is exactly where it
            // was and the next read tries again.
            KLogger.e(it) { "vault migration failed - the legacy vault is untouched and still readable" }
        }
    }

    private fun retainDowngradeCopy(username: String, vault: OpenVault) {
        if (storage.retainPreMigration(username, vault.ciphertext)) {
            KLogger.i { "vault migration: retained the pre-migration ciphertext for downgrade" }
        }
    }

    /**
     * Seal [plaintext] and prove the result opens *before* it is allowed near the vault file.
     *
     * "The write succeeded" says the bytes reached the disk, not that they mean anything. A sealed
     * vault that cannot be reopened is indistinguishable from a good one until the next login, at
     * which point the vault it replaced is gone. The decrypt here costs one AES-GCM pass over a small
     * file and is the last moment at which discovering the problem is free.
     */
    private fun sealAndVerify(username: String, plaintext: ByteArray, sessionKey: VaultSessionKey): ByteArray {
        val portable = portableVaultFormat
        val sealed = portable?.seal(username, plaintext, sessionKey) ?: vaultCipher.encryptVault(plaintext, sessionKey)
        val reopened = portable?.open(username, sealed, sessionKey)
            ?: vaultCipher.decryptVault(sealed, sessionKey) { null }.plaintext
        check(reopened.contentEquals(plaintext)) {
            "the sealed vault did not reopen to the plaintext it was built from"
        }
        return sealed
    }

    private fun sessionKey(scope: Scope): VaultSessionKey =
        scope.get<VaultSession>(named(VAULT_SESSION_HANDLE)).require()

    /**
     * The session's RSA identity key, or null when this device has none to offer.
     *
     * Resolved through a `runCatching` rather than `getOrNull` because the definition takes two
     * parameters: on a scope login never warmed, resolving it without them fails inside Koin rather
     * than returning null. Either way the answer is the same — no legacy key — and
     * `VaultCipher.decryptVault` turns that into a typed
     * `VaultFailure.Malformed(legacyKeyUnavailable = true)` instead of a crash.
     */
    private fun legacyPrivateKey(scope: Scope): CryptoKey? =
        runCatching { scope.get<CryptoKey>(named(PRIVATE_DECRYPTION_KEY_HANDLE)) }
            .onFailure { KLogger.w { "legacy vault read: no RSA identity in this session (${it::class.simpleName})" } }
            .getOrNull()
}

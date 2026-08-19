package ai.passman.platform.repository

import ai.passman.platform.crypto.Sha256Service
import ai.passman.domain.password.model.PasswordEntry
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/** A uuid is 128 bits, and `Uuid.fromByteArray` requires exactly that many. */
private const val UUID_BYTES = 16

/**
 * Separates the two halves of the legacy preimage.
 *
 * Without it `("gmail", "alice")` and `("gmai", "lalice")` would hash the same bytes and derive one
 * identity. NUL is used because neither field can usefully contain one — every producer of both is a
 * text field in the UI.
 */
private const val FIELD_SEPARATOR: Byte = 0

/**
 * Where a [PasswordEntry.uuid] comes from.
 *
 * ## Why legacy uuids are derived rather than drawn
 *
 * Two devices upgrade independently and never talk to each other about it. Whatever identity they
 * assign to a pre-existing entry, they have to assign the *same* one, or the first merge afterwards
 * sees two rows where the user has one and duplicates the entire vault — permanently, since both
 * copies then go on being edited. A random uuid at migration time is exactly that failure, so the
 * legacy value is a pure function of data both devices already hold identically.
 *
 * The preimage is `entryName | 0x00 | username`. Both fields qualify: two copies of one logical entry
 * agree on both by construction, because the pre-uuid merge keyed on the name and carried the
 * username along with it. [PasswordEntry.dateCreated] does not qualify and is deliberately excluded:
 * conflict resolution is *built* on that field differing between the two copies, so hashing it in
 * would hand the two devices different uuids and cause the very duplication this exists to prevent.
 * [PasswordEntry.id] does not qualify either — it is a display ordinal and depends on what else is in
 * the vault.
 *
 * ## Why the name alone is not enough
 *
 * Nothing enforces name uniqueness on create, so a vault holding `[gmail/alice, gmail/bob]` is one
 * tap away. Derived from the name alone, those two rows share a single identity — and every mutation
 * in [LocalPasswordRepository] resolves its target by uuid across the whole entry list. Deleting one
 * destroyed the other, editing one overwrote the other, and opening the second returned the first.
 * Locally, silently, with no sync involved.
 *
 * Widening the preimage separates them and costs nothing on the sync side, because both devices hold
 * the same username for the same entry. The only thing it changes about the first merge after the
 * upgrade is that rows which used to collapse into one now both survive — the data-loss bug being
 * fixed, not a regression.
 *
 * ## What the widening does not fix
 *
 * Two entries sharing *both* a name and a username are genuinely indistinguishable: there is no third
 * field two devices are guaranteed to agree on, so they derive one identity and still collapse on
 * merge. What is bounded is the local damage — the mutations in [LocalPasswordRepository] act on at
 * most one row no matter how many share a uuid, so that case costs the user "the wrong twin was
 * edited", never "both twins were destroyed".
 *
 * The residual cross-device case is a username edited on one device *before* either upgraded: the two
 * sides then derive different uuids for what is one entry, and the first merge afterwards leaves the
 * user holding both copies. That trade is deliberate. A duplicate is visible and can be deleted;
 * the collapse it replaces silently destroyed a credential. Duplication is recoverable, deletion is
 * not.
 *
 * ## Why derivation is idempotent rather than a migration step
 *
 * [stabilize] runs on every read of a vault that still has entries without a uuid, and produces the
 * same answer every time. Nothing has to be rewritten for it to be correct, so it needs no migration
 * window and no risk of a half-converted vault; the derived values simply become durable the next
 * time something writes for its own reasons.
 */
class PasswordEntryIdentity(private val sha256: Sha256Service) {

    /** A fresh identity for an entry that does not exist yet. */
    @OptIn(ExperimentalUuidApi::class)
    fun newUuid(): String = Uuid.random().toString()

    /** The identity of an entry written before uuids existed. Deterministic across devices. */
    @OptIn(ExperimentalUuidApi::class)
    fun legacyUuid(entryName: String, username: String): String =
        Uuid.fromByteArray(sha256.sha256(preimage(entryName, username)).copyOf(UUID_BYTES)).toString()

    /**
     * [entries] with a uuid on every row.
     *
     * Returns the receiver untouched when there is nothing to assign, so a vault that has already
     * been through this does not allocate a second list on every read.
     */
    fun stabilize(entries: List<PasswordEntry>): List<PasswordEntry> =
        if (entries.none { it.uuid.isEmpty() }) {
            entries
        } else {
            entries.map {
                if (it.uuid.isEmpty()) it.copy(uuid = legacyUuid(it.entryName, it.username)) else it
            }
        }

    /** `entryName | 0x00 | username`, built explicitly so the layout is impossible to misread. */
    private fun preimage(entryName: String, username: String): ByteArray {
        val name = entryName.encodeToByteArray()
        val user = username.encodeToByteArray()
        val bytes = ByteArray(name.size + 1 + user.size)
        name.copyInto(bytes)
        bytes[name.size] = FIELD_SEPARATOR
        user.copyInto(bytes, name.size + 1)
        return bytes
    }
}

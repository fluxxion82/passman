package ai.passman.platform.repository

import ai.passman.domain.password.model.EntryActivity
import ai.passman.domain.password.model.PasswordEntry

/**
 * How long a deleted row stays in the vault as a tombstone: 90 days.
 *
 * A tombstone only has to outlive the window in which some peer might still be holding the live row
 * and re-offering it on the next merge. Keeping them forever would grow the vault monotonically and
 * leave the *names* of deleted entries lying in it indefinitely; 90 days is far beyond any plausible
 * gap between two devices that sync at all. Past it the row is dropped outright, and a peer that has
 * been dark for longer than that can indeed re-add the entry — the same trade every tombstone scheme
 * makes, and the one that keeps the vault from growing without bound.
 */
internal const val TOMBSTONE_TTL_MILLIS = 90L * 24 * 60 * 60 * 1000

/**
 * The display ordinal a tombstoned row carries.
 *
 * Tombstones are never shown, so they must not *consume* an ordinal either: every read renumbers the
 * live rows `1..N` and a tombstone that took a number would leave a hole in the sequence the user can
 * see. `"0"` is outside the `1..N` range every live row lives in, and parses to the same `0` that
 * `addPasswordEntry`'s `maxOfOrNull { it.id.toIntOrNull() ?: 0 }` already treats as "contributes
 * nothing", so a vault full of tombstones cannot push the next new entry's ordinal upwards.
 */
internal const val TOMBSTONE_ORDINAL = "0"

/**
 * Whether this row has been deleted.
 *
 * Deletion is recorded as an [EntryActivity.KIND_DELETED] record rather than as a field on
 * [PasswordEntry] — see that constant's KDoc for why a new boolean field would be stripped by an
 * older peer and resurrect the entry.
 */
internal val PasswordEntry.isTombstoned: Boolean
    get() = activity.any { it.kind == EntryActivity.KIND_DELETED }

/**
 * When this row was deleted, or null when it is alive.
 *
 * The *latest* deletion record, not the earliest: two devices can each stamp their own record for the
 * same row (they delete independently, before ever syncing), and the union keeps both. Expiring
 * against the earliest would let one side drop the row while the other still holds a younger
 * tombstone for it — the older side would then take the peer's tombstone back on the next merge and
 * the pair would never settle. Taking the maximum makes the expiry deadline a property of the set of
 * records, so both sides reach it at the same instant.
 */
internal val PasswordEntry.deletedAt: Long?
    get() = activity.filter { it.kind == EntryActivity.KIND_DELETED }.maxOfOrNull { it.at }

/**
 * This row, deleted at [now].
 *
 * Everything except the ordinal and the activity list is kept, and that is deliberate on two counts.
 * [PasswordEntryIdentity] derives a legacy uuid from `entryName | 0x00 | username`, so blanking those
 * would change the row's identity and it would stop matching the peer's live copy — which is the one
 * thing that makes the whole mechanism pointless. And blanking the *secret* fields would mean a
 * build old enough to drop the activity list entirely (see [EntryActivity.KIND_DELETED]) resurrects
 * an entry with an empty password rather than merely resurrecting it, turning an accepted annoyance
 * into destroyed data.
 *
 * [PasswordEntry.dateCreated] is left alone as well. It is the merge's scalar tie-break, and the
 * tombstone is checked *before* that comparison, so bumping it would buy nothing and would put a raw
 * device wall clock in charge of whether a deletion sticks.
 */
internal fun PasswordEntry.tombstoned(now: Long): PasswordEntry = copy(
    id = TOMBSTONE_ORDINAL,
    activity = mergeActivity(activity, listOf(EntryActivity(now, EntryActivity.KIND_DELETED))),
)

/** The live rows of this list — what every read outside the merge and the write path may see. */
internal fun List<PasswordEntry>.live(): List<PasswordEntry> = filterNot { it.isTombstoned }

/**
 * This list with tombstones older than [TOMBSTONE_TTL_MILLIS] removed — the row goes with the
 * tombstone, since the row is only still here to carry it.
 *
 * Written as `now - deletedAt > TTL` rather than `deletedAt < now - TTL` so a record stamped by a
 * peer whose clock runs ahead reads as "not expired yet" instead of underflowing into some
 * arbitrary answer. Erring towards keeping a tombstone costs a hidden row; erring the other way
 * resurrects a credential the user deleted.
 */
internal fun List<PasswordEntry>.withoutExpiredTombstones(now: Long): List<PasswordEntry> =
    if (none { it.isTombstoned }) {
        this
    } else {
        filterNot { entry ->
            val deletedAt = entry.deletedAt ?: return@filterNot false
            now - deletedAt > TOMBSTONE_TTL_MILLIS
        }
    }

/**
 * Display ordinals `1..N` over the live rows, in the order this list is already in.
 *
 * Kept separate from the sort because [ai.passman.platform.repository.LocalPasswordRepository]'s read
 * path needs the sorted list and the renumbered list as two values, and both merge sites need the
 * sort *and* the renumbering. Tombstones are skipped rather than numbered — see [TOMBSTONE_ORDINAL].
 */
internal fun List<PasswordEntry>.withDisplayOrdinals(): List<PasswordEntry> {
    var ordinal = 0
    return map { if (it.isTombstoned) it.copy(id = TOMBSTONE_ORDINAL) else it.copy(id = (++ordinal).toString()) }
}

/**
 * Two copies of one entry — same [PasswordEntry.uuid] — reduced to the one the vault keeps.
 *
 * ## Why this is a function and not two `when` arms at each merge site
 *
 * There are two merge sites (`LocalPasswordRepository.mergePasswordEntries` and the inline copy in
 * `VaultReconciler`), and each used to spell its winner decision as
 * `current == null || entry.dateCreated > current.dateCreated`, where **the else arm does nothing**.
 * Every rule that has to apply regardless of which copy wins — the activity union, the `createdAt`
 * minimum, and now the tombstone check — then has to be written back into all four arms by hand, and
 * a rule written into only the winning one applies only when the incoming row happens to be newer:
 * the two vaults quietly stop converging instead of failing. Collapsing the decision into one
 * function removes the arms entirely, which is the only version of "remember to do it in both
 * places" that cannot rot. `current == null` stays at the call sites, because there is no pair to
 * reduce there.
 *
 * ## Delete beats a newer edit, and is checked before [PasswordEntry.dateCreated]
 *
 * "I deleted this and it came back" is a far worse outcome than "I deleted it on the wrong device
 * and re-added it", and the scalar comparison below runs on raw device wall clocks — a skewed clock
 * deciding whether a credential survives is not a trade worth making. So a tombstoned copy wins
 * outright over a live one, in either direction, and only when the two copies agree on being deleted
 * (or on being alive) does `dateCreated` get a say. There is no undelete: nothing in this function
 * can turn a tombstoned pair back into a live row.
 *
 * The union underneath would very nearly do this on its own — [mergeActivity] carries the deletion
 * record onto whichever row wins, so the result is tombstoned either way — but relying on that would
 * mean the peer's post-delete edit overwrote the stored row's fields for no benefit, and it would
 * leave the rule invisible at the point it is being made.
 *
 * ## Commutativity
 *
 * `mergeEntry(a, b)` and `mergeEntry(b, a)` agree on everything this function decides: the tombstone
 * check is symmetric, [mergeActivity] and [minNonZero] are both commutative, and the `dateCreated`
 * comparison is strict so it picks the same row from either side. The one asymmetry is the tie —
 * equal `dateCreated`, differing fields — where the local copy stays, which is the documented
 * pre-existing behaviour of this merge and not something the tombstone rule changes.
 */
internal fun mergeEntry(current: PasswordEntry, incoming: PasswordEntry): PasswordEntry {
    val winner = when {
        current.isTombstoned != incoming.isTombstoned -> if (current.isTombstoned) current else incoming
        incoming.dateCreated > current.dateCreated -> incoming
        else -> current
    }
    return winner.copy(
        activity = mergeActivity(current.activity, incoming.activity),
        createdAt = minNonZero(current.createdAt, incoming.createdAt),
    )
}

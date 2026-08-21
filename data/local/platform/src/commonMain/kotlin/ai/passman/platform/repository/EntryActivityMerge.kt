package ai.passman.platform.repository

import ai.passman.domain.password.model.EntryActivity

/**
 * How many [EntryActivity] records survive on one entry.
 *
 * The vault is one JSON blob, re-encrypted whole on every write and synced whole on every pull —
 * there is no per-record transfer to economise on. At roughly 40-70 bytes per record, twenty of them
 * on every entry of a large, heavily-edited vault is still only a few hundred KB worst case, which is
 * the trade this number makes: enough history to be useful, never enough to make the vault itself
 * expensive to move.
 */
internal const val MAX_ACTIVITY = 20

/**
 * The union of two activity lists for one entry, capped to [MAX_ACTIVITY].
 *
 * This is the one implementation every call site that *grows an existing* activity list uses — an
 * edit append and both merge sites (`LocalPasswordRepository.mergePasswordEntries` and
 * `VaultReconciler`'s merge branch) — deliberately not duplicated between them. Creation is not one
 * of these: a brand-new entry has no prior list to union against, so `addPasswordEntry` seeds
 * `listOf(EntryActivity(now, KIND_CREATED))` directly instead of calling this function. The merge rule
 * below carries real semantics, and two hand-maintained copies is how they drift the first time one of
 * them is touched and the other is not.
 *
 * ## Every merge call site must write this back in *both* arms of its winner decision
 *
 * This function only does its job if it is actually called on every merge, and a merge site that
 * unions activity only when the incoming row wins its scalar `dateCreated` comparison is the obvious
 * implementation — and it is broken. When the *local* copy wins, the incoming side's unique activity
 * records are dropped and its earlier `createdAt` (see [minNonZero]) is never consulted. Each device
 * then keeps its own separate history: the mirror merge on the peer unions in the *other* direction,
 * so the two vaults' activity lists never converge, and the next strictly-newer edit drags one side's
 * list back across the sync — history flip-flops between syncs instead of settling. `min()` would be
 * unreachable in exactly the cases it exists for. So both arms of `current == null || entry.dateCreated
 * > current.dateCreated` must call this function (and [minNonZero]), not only the branch where the
 * incoming row replaces the current one.
 *
 * ## Why `.distinct()` runs before the sort, on the whole record
 *
 * A projected dedup key (e.g. `distinctBy { it.at }`) would silently exclude a field from a record's
 * identity forever. `.distinct()` compares the whole data class, so a fourth field added to
 * [EntryActivity] later is automatically part of what makes two records "the same", with no call site
 * here to remember to update.
 *
 * ## Why the sort is `compareBy(at, kind, device)` and not `sortedBy { it.at }`
 *
 * `sortedBy` alone is not a total order: Kotlin's sort is stable, so when two records tie on `at` the
 * order between them is whatever order they arrived in the *concatenation*, i.e. it depends on
 * argument order. That makes the record that survives the [MAX_ACTIVITY] cap boundary depend on
 * whether this function was called as `mergeActivity(a, b)` or `mergeActivity(b, a)` — so the
 * operation is neither commutative nor idempotent, exactly at the boundary where it matters most.
 * Ties are not hypothetical: `device` is `""` for every entry in this schema step, so two devices
 * editing the same entry in the same millisecond tie on `at` and on `device` both.
 *
 * Sorting on the full tuple `(at, kind, device)` removes the ambiguity: with a true total order,
 * "the newest [MAX_ACTIVITY] of a set" is a function of the *set*, not of how it was assembled, so it
 * is stable under re-union with any subset of itself — which is what makes
 * `mergeActivity(mergeActivity(a, b), b) == mergeActivity(a, b)` (idempotence) and
 * `mergeActivity(a, b) == mergeActivity(b, a)` (commutativity) both hold, including at the cap
 * boundary. Do not "simplify" this back to `sortedBy { it.at }` — that reintroduces the
 * non-determinism this sort exists to remove.
 *
 * Unlike `.distinct()` above, this comparator does *not* pick up a new field automatically: a fourth
 * field added to [EntryActivity] later must be added to [ACTIVITY_ORDER] by hand, or two records
 * differing only in that field tie under the old tuple, the order stops being total again, and
 * idempotence and commutativity break silently, again exactly at the cap boundary.
 *
 * ## Why an [EntryActivity.KIND_DELETED] record is exempt from eviction
 *
 * A deletion record *is* the tombstone — the row is hidden from every read because it carries one,
 * and for no other reason. Let the cap evict it and a busy entry (twenty edits is not a lot for a
 * password that gets rotated) silently comes back to life on the next merge, which is the failure
 * this whole mechanism exists to prevent and is strictly worse than losing a line of history.
 *
 * So deletion records are taken first and ordinary ones fill whatever room is left. The cap still
 * holds at [MAX_ACTIVITY] in total rather than becoming "twenty *plus* the tombstones": deletion
 * records are themselves capped, so a corrupt or hostile vault carrying thousands of them cannot use
 * the exemption to grow an entry without bound, and keeping the newest twenty of them still leaves
 * the row unmistakably tombstoned.
 *
 * The result stays a pure function of the *set* of records under a total order — the property the
 * comparator above exists to buy — so commutativity and idempotence survive the exemption: merging
 * `b` back into `mergeActivity(a, b)` re-offers only records that were already considered and lost,
 * and they lose again by the same comparison.
 */
internal fun mergeActivity(a: List<EntryActivity>, b: List<EntryActivity>): List<EntryActivity> {
    val all = (a + b).distinct().sortedWith(ACTIVITY_ORDER)
    val deletions = all.filter { it.kind == EntryActivity.KIND_DELETED }
    if (deletions.isEmpty()) return all.takeLast(MAX_ACTIVITY)
    val keptDeletions = deletions.takeLast(MAX_ACTIVITY)
    val room = MAX_ACTIVITY - keptDeletions.size
    val keptRest = all.filterNot { it.kind == EntryActivity.KIND_DELETED }.takeLast(room)
    return (keptDeletions + keptRest).sortedWith(ACTIVITY_ORDER)
}

/** The total order [mergeActivity] both sorts and evicts by. See its KDoc for why it is total. */
private val ACTIVITY_ORDER = compareBy<EntryActivity>({ it.at }, { it.kind }, { it.device })

/**
 * The earlier of two [ai.passman.domain.password.model.PasswordEntry.createdAt] values, treating `0`
 * ("never backfilled") as absent rather than as the smallest possible timestamp.
 *
 * A plain `minOf(a, b)` would let a `0` win forever, which is backwards: `0` does not mean "infinitely
 * old", it means "this copy has not gone through `PasswordEntryIdentity.stabilize` yet". `minNonZero(0,
 * 0)` — neither side backfilled — answers `0` and must not throw; the value is not yet meaningful
 * either way, and the field gets backfilled the next time either copy is read.
 *
 * Convergence argument: the backfill derives `createdAt := dateCreated`, the row's own field, never a
 * wall clock. Two devices holding the same `dateCreated` — what a pre-upgrade sync guarantees — derive
 * the same `createdAt`, so a divergent `createdAt` implies a divergent `dateCreated`, which is exactly
 * where the entry-level merge's strictly-newer rule fires and this function runs. Candidates handed to
 * it are non-decreasing over time (a device's own `dateCreated` only grows), so the minimum it latches
 * onto cannot walk backwards and cannot oscillate between syncs.
 */
internal fun minNonZero(a: Long, b: Long): Long = when {
    a == 0L -> b
    b == 0L -> a
    else -> minOf(a, b)
}

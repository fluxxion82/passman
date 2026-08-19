package ai.passman.domain.password.model

import kotlinx.serialization.Serializable

/**
 * One stored credential.
 *
 * ## [uuid] addresses the entry; [id] only orders it
 *
 * [id] is a *display ordinal*. Every read sorts by [entryName] and reassigns `1..N`, and every merge
 * does the same at the end, so the number an entry carries describes the list it currently sits in
 * rather than the entry itself. Addressing a mutation by it is therefore a race: the vault can be
 * renumbered between the moment a caller reads an id and the moment its write lands, at which point
 * the id names a *different* credential — a delete that removes the wrong one and reports success.
 *
 * [uuid] is the identity. It is assigned once and never re-derived afterwards:
 *
 * - entries created from now on get a random uuid;
 * - entries that predate this field get
 *   `Uuid.fromByteArray(sha256(entryName | 0x00 | username).copyOf(16))`, derived when they are read
 *   and persisted by the next write.
 *
 * The legacy derivation uses [entryName] and [username] and nothing else, because two devices have to
 * arrive at the *same* uuid for the same pre-existing entry with no coordination between them, and
 * those are the two fields both copies hold identically. Folding [dateCreated] in would break
 * precisely that: conflict resolution expects that field to differ between two copies of one logical
 * entry, so the two devices would derive two different uuids and the first sync after the upgrade
 * would duplicate everything the user owns. Dropping [username] and keying on the name alone breaks
 * it from the other side: nothing enforces name uniqueness, so two logins for one site would share an
 * identity, and every mutation that resolves a target by uuid would act on both of them.
 *
 * ## The default is for deserialization, and the compiler will not warn you
 *
 * A vault written before this field has no `uuid` key, and an empty value means "not assigned yet —
 * derive it". Nothing handed out by the repository carries an empty [uuid].
 *
 * Because the default sits last, a *positional* construction —
 * `PasswordEntry("1", "gmail", "u", "p", "w", "n", 1000L)` — compiles and yields an entry with no
 * identity, which is indistinguishable from a legacy row and will be assigned a derived uuid rather
 * than the caller's. Name the arguments, and give [uuid] a value for anything that is not being
 * deserialized.
 */
@Serializable
data class PasswordEntry(
    val id: String,
    val entryName: String,
    val username: String,
    val password: String,
    val website: String,
    val notes: String,
    val dateCreated: Long,
    val uuid: String = "",
    /** Raw base32 secret or full otpauth:// uri; empty when the entry has no second factor. */
    val totpSeed: String = "",
    val customFields: List<CustomField> = emptyList(),
    /**
     * When this entry was actually first created — unlike [dateCreated], which despite its name is
     * overwritten on every edit (`LocalPasswordRepository.updatePasswordEntry`) and doubles as the
     * merge key at both sync sites. Renaming that field would touch every merge and every caller that
     * already reads it as "last edited"; this field exists instead, to mean what its name says.
     *
     * Defaulted to `0` for the same reason [uuid] defaults to `""`: a row written before this field
     * existed has no value for it, and `0` is not a real timestamp, so it doubles as "not yet known —
     * backfill it", the way an empty [uuid] means "not yet assigned — derive it". `stabilize` in
     * `PasswordEntryIdentity` does that backfill, from [dateCreated] — the only timestamp a
     * pre-upgrade row ever had, so created and last-edited start out equal for it. See `minNonZero` in
     * `data/local/platform` for how two independently-backfilled copies of one entry converge on
     * merge.
     */
    val createdAt: Long = 0,
    /**
     * This entry's history: created, edited, and (once a later task populates [EntryActivity.device])
     * which device did it.
     *
     * Not guaranteed sorted by construction. `mergeActivity` in `data/local/platform` is the one place
     * that both orders it and caps it at `MAX_ACTIVITY`, and every call site that grows this list past
     * its first record — an edit, or either merge site — goes through it, so a second hand-rolled
     * append-and-trim never drifts from the merge's notion of "keep the newest". Creation seeds the
     * list directly with its single [EntryActivity.KIND_CREATED] record, which starts life under the
     * cap with nothing to merge against.
     */
    val activity: List<EntryActivity> = emptyList(),
)

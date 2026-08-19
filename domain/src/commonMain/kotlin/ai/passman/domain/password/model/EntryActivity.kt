package ai.passman.domain.password.model

import kotlinx.serialization.Serializable

/**
 * One recorded moment in a [PasswordEntry]'s history: created, edited, and — once a later task
 * populates [device] — which device did it. [device] is declared now and left empty deliberately;
 * the point of declaring it ahead of the task that fills it in is that every peer already on this
 * schema preserves it once some build starts writing it, rather than dropping an unknown field.
 *
 * ## Why [kind] is a `String`, not an enum
 *
 * `VaultJson`'s `ignoreUnknownKeys` tolerates an unknown *key* on decode; kotlinx.serialization gives
 * no equivalent tolerance to an unknown *enum value* — decoding one throws `SerializationException`
 * and fails the whole entry list, not just this record (verified against kotlinx-serialization
 * 1.11.0). An enum here would mean the first build that adds a fifth kind makes every older build
 * unable to open a synced vault.
 *
 * The safer-looking enum encodings are worse, for a subtler reason than the crash. `coerceInputValues
 * = true` with a defaulted `UNKNOWN` member, or a custom serializer with an `UNKNOWN` fallback, both
 * **destroy the original value on the older build's next re-encode**: `"totp-viewed"` is written back
 * as `"UNKNOWN"`. Because the merge that unions activity dedupes on record contents, the mangled copy
 * and the real one then coexist as a permanent duplicate that no later merge can collapse. A plain
 * `String` round-trips an unrecognised kind verbatim through an old build, which is the actual
 * forward-compat property this field exists to buy.
 *
 * Readers must treat an unrecognised kind as "something happened", render it generically, and never
 * crash on it — never assume every record is one of [KIND_CREATED] / [KIND_EDITED].
 *
 * Wire values are format, not code style, and are pinned here: `"created"`, `"edited"`.
 */
@Serializable
data class EntryActivity(
    val at: Long,
    val kind: String,
    val device: String = "",
) {
    companion object {
        const val KIND_CREATED = "created"
        const val KIND_EDITED = "edited"
    }
}

package ai.passman.domain.settings.model

import kotlinx.serialization.Serializable

/**
 * One row of this device's sync activity log: what was synced, with which paired device, when,
 * and how it ended. Answers the beta complaint that peer-to-peer sync is opaque — after a sync the
 * user can open Settings and see exactly this.
 *
 * ## This log is per-device and is never synced
 *
 * It records what *this* device did; replicating it to a peer would be circular (a log of syncs
 * traveling inside a sync), and it holds peer hostnames and device names that have no business
 * inside a vault that copies to every paired device.
 *
 * That is free by construction, not by a filter: `DirectoryBundler.bundle` — the only thing that
 * turns a local directory into wire bytes — is called on exactly `pgp/<user>/` and
 * `keystore/<user>/` (`FileTransferRepository.kt`, `LocalKeystoreRepository.kt`,
 * `LocalPgpRepository.kt`), and the password vault is transferred as a database file, not a
 * bundled directory, at another call site entirely. This log lives in its own encrypted
 * `Settings` store (see `LocalSyncLogRepository`), a preferences transport `DirectoryBundler`
 * never touches — and `DirectoryBundler.syncExclusions` could not name it even if it needed to,
 * since that set matches exact basenames *inside* a directory being bundled, and a preferences
 * node is not a file inside anything `DirectoryBundler` ever walks. The actual trigger that would
 * put this log at risk: relocating it out of `Settings` into a file under the app's data
 * directory, or adding any whole-profile export path — either would give this log a way off the
 * device outside the push/pull transports `DirectoryBundler` guards, the same way
 * `JvmPasswordDatabaseStorage` warns that `.premigration.v2` needs an exclusion before `database/`
 * could ever be bundled.
 *
 * ## Why [outcome] is a `String`, not an enum
 *
 * Same reasoning as [ai.passman.domain.password.model.EntryActivity.kind]: this log is decoded
 * from JSON written by whatever build wrote it, and kotlinx.serialization has no tolerance for an
 * unknown *enum value* the way `ignoreUnknownKeys` tolerates an unknown key — decoding one throws
 * and would make a build that has been downgraded (or simply predates a new outcome) unable to
 * open its own log. A plain `String` round-trips an unrecognised outcome verbatim. Readers must
 * treat one as "something happened" via a `when` with an `else`, never assume every record is one
 * of [OUTCOME_SUCCESS] / [OUTCOME_FAILED] / [OUTCOME_CANCELLED].
 *
 * ## Why [detail] is safe to show
 *
 * [detail] carries the human-readable failure reason and nothing else — never a fingerprint,
 * never vault content, never a secret. [host] and [deviceName] are the only identity data
 * recorded, and both are already visible in the paired-devices UI, so this log discloses nothing
 * a user could not already see there.
 */
@Serializable
data class SyncLogEntry(
    val at: Long,
    val artifact: String,
    val host: String,
    val deviceName: String = "",
    val outcome: String,
    val detail: String = "",
) {
    companion object {
        const val OUTCOME_SUCCESS = "success"
        const val OUTCOME_FAILED = "failed"
        const val OUTCOME_CANCELLED = "cancelled"
    }
}

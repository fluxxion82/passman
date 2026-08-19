package ai.passman.logging

/**
 * Drops log events below [minimumPriority] and forwards the rest to [delegate].
 *
 * Release builds use this to keep warnings and errors while discarding debug and verbose
 * output. That matters here beyond noise: debug logging in this app records vault paths,
 * keystore file names and user names — for example "new keystore <user>.pfx at location
 * /data/user/0/.../files/keystore/<user>" — and FileLogger persists those to disk. None of
 * that should survive into a release build, while a warning or error still should, so a
 * failure in the field remains diagnosable.
 *
 * Filtering lives here rather than in KLogger because KLogger fans out to every registered
 * logger; a per-logger threshold lets one sink stay verbose while another does not.
 */
class MinimumPriorityLogger(
    private val delegate: Logger,
    private val minimumPriority: Logger.Priority = Logger.Priority.WARNING,
) : Logger {

    @Suppress("LongParameterList")
    override fun log(
        priority: Logger.Priority,
        explicitTag: String?,
        inferredTag: String,
        message: String?,
        throwable: Throwable?,
        properties: Map<String, String>?,
    ) {
        if (priority.ordinal < minimumPriority.ordinal) return
        delegate.log(priority, explicitTag, inferredTag, message, throwable, properties)
    }
}

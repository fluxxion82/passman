package ai.passman.logging

import ai.passman.logging.Logger.Priority

@Suppress("NOTHING_TO_INLINE", "TooManyFunctions")
object KLogger {
    private var properties: Map<String, String>? = null

    private var loggers = mutableListOf<Logger>()

    private var explicitTag = Tag("")

    fun registerLoggers(logger: Logger, vararg other: Logger) {
        loggers.add(logger)
        loggers.addAll(other)
    }

    fun registerLoggers(loggers: Collection<Logger>) {
        KLogger.loggers.addAll(loggers)
    }

    fun unregisterLoggers(logger: Logger, vararg other: Logger) {
        loggers.remove(logger)
        loggers.removeAll(other)
    }

    fun unregisterLoggers(loggers: Collection<Logger>) {
        KLogger.loggers.removeAll(loggers)
    }

    fun v(message: () -> String) {
        performLog(
            Priority.VERBOSE,
            message = message,
            throwable = null
        )
    }

    fun v(throwable: Throwable, message: () -> String) {
        performLog(
            Priority.VERBOSE,
            throwable = throwable,
            message = message
        )
    }

    fun v(throwable: Throwable) {
        performLog(
            Priority.VERBOSE,
            message = null,
            throwable = throwable
        )
    }

    fun d(message: () -> String) {
        performLog(
            Priority.DEBUG,
            message = message,
            throwable = null
        )
    }

    fun d(throwable: Throwable, message: () -> String) {
        performLog(
            Priority.DEBUG,
            throwable = throwable,
            message = message
        )
    }

    fun d(throwable: Throwable) {
        performLog(
            Priority.DEBUG,
            message = null,
            throwable = throwable
        )
    }

    fun i(message: () -> String) {
        performLog(Priority.INFO, message = message, throwable = null)
    }

    fun i(throwable: Throwable, message: () -> String) {
        performLog(
            Priority.INFO,
            throwable = throwable,
            message = message
        )
    }

    fun i(throwable: Throwable) {
        performLog(
            Priority.INFO,
            message = null,
            throwable = throwable
        )
    }

    fun w(message: () -> String) {
        performLog(
            Priority.WARNING,
            message = message,
            throwable = null
        )
    }

    fun w(throwable: Throwable, message: () -> String) {
        performLog(
            Priority.WARNING,
            throwable = throwable,
            message = message
        )
    }

    fun w(throwable: Throwable) {
        performLog(
            Priority.WARNING,
            message = null,
            throwable = throwable
        )
    }

    fun e(message: () -> String) {
        performLog(
            Priority.ERROR,
            message = message,
            throwable = null
        )
    }

    fun e(throwable: Throwable, message: () -> String) {
        performLog(
            Priority.ERROR,
            throwable = throwable,
            message = message
        )
    }

    fun e(throwable: Throwable) {
        performLog(
            Priority.ERROR,
            message = null,
            throwable = throwable
        )
    }

    fun wtf(message: () -> String) {
        performLog(Priority.WTF, message = message, throwable = null)
    }

    fun wtf(throwable: Throwable, message: () -> String) {
        performLog(
            Priority.WTF,
            throwable = throwable,
            message = message
        )
    }

    fun wtf(throwable: Throwable) {
        performLog(
            Priority.WTF,
            message = null,
            throwable = throwable
        )
    }

    fun log(priority: Priority, message: () -> String) {
        performLog(priority, message = message, throwable = null)
    }

    fun log(priority: Priority, throwable: Throwable, message: () -> String) {
        performLog(priority, throwable = throwable, message = message)
    }

    fun log(priority: Priority, throwable: Throwable) {
        performLog(priority, message = null, throwable = throwable)
    }

    fun tag(explicit: String): KLogger {
        explicitTag.explicit = explicit
        return this
    }

    fun properties(values: Map<String, String>): KLogger {
        properties = values.toMap()
        return this
    }

    fun properties(vararg values: Pair<String, String>): KLogger {
        properties = mapOf(*values)
        return this
    }

    private fun performLog(
        priority: Priority,
        throwable: Throwable?,
        message: (() -> String)?
    ) {
        val tag = explicitTag
        explicitTag.explicit = null

        val props = properties
        properties = null

        val messageString by lazy(mode = LazyThreadSafetyMode.NONE) {
            message?.invoke()
        }

        val inferred = inferTag()
        loggers.forEach {
            it.log(
                priority = priority,
                explicitTag = tag.explicit,
                inferredTag = inferred,
                throwable = throwable,
                message = messageString,
                properties = props
            )
        }
    }
}

data class Tag(var explicit: String?)

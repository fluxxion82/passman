package ai.passman.logging.jvm

import ai.passman.logging.Logger

object JvmLogger : Logger {
    // private val anonLogger = JavaLog.getAnonymousLogger()

    @Suppress("ComplexMethod")
    override fun log(
        priority: Logger.Priority,
        explicitTag: String?,
        inferredTag: String,
        message: String?,
        throwable: Throwable?,
        properties: Map<String, String>?
    ) {
        val tagToLog = explicitTag ?: inferredTag
        val messageToLog = message ?: throwable?.message.orEmpty()

        when (priority) {
            Logger.Priority.VERBOSE -> {
                throwable?.let {
                    println("${arrayOf(tagToLog, it).joinToString(":")}:$messageToLog")
                    // anonLogger.log(Level.ALL, messageToLog, arrayOf(tagToLog, it))
                } ?: println("$tagToLog:$messageToLog") // anonLogger.log(Level.ALL, messageToLog, tagToLog)
            }
            Logger.Priority.INFO -> {
                throwable?.let {
                    println("I ${arrayOf(tagToLog, it).joinToString(":")}:$messageToLog")
                    // anonLogger.log(Level.INFO, messageToLog, arrayOf(tagToLog, it))
                } ?: println("I $tagToLog:$messageToLog") //anonLogger.log(Level.INFO, messageToLog, tagToLog)
            }
            Logger.Priority.DEBUG -> {
                throwable?.let {
                    println("D ${arrayOf(tagToLog, it).joinToString(":")}:$messageToLog")
                    // anonLogger.log(Level.CONFIG, messageToLog, arrayOf(tagToLog, it))
                } ?: println("D $tagToLog:$messageToLog") // anonLogger.log(Level.CONFIG, messageToLog, tagToLog)
            }
            Logger.Priority.WARNING -> {
                throwable?.let {
                    println("W ${arrayOf(tagToLog, it).joinToString(":")}:$messageToLog")
                    // anonLogger.log(Level.WARNING, messageToLog, arrayOf(tagToLog, it))
                } ?: println("W $tagToLog:$messageToLog") // anonLogger.log(Level.WARNING, messageToLog, tagToLog)
            }
            Logger.Priority.ERROR -> {
                throwable?.let {
                    println("E ${arrayOf(tagToLog, it).joinToString(":")}:$messageToLog")
                    // anonLogger.log(Level.SEVERE, messageToLog, arrayOf(tagToLog, it))
                } ?: println("E $tagToLog:$messageToLog") // anonLogger.log(Level.SEVERE, messageToLog, tagToLog)
            }
            Logger.Priority.WTF -> {
                throwable?.let {
                    println("WTF ${arrayOf(tagToLog, it).joinToString(":")}:$messageToLog")
                    // anonLogger.log(Level.SEVERE, messageToLog, arrayOf(tagToLog, it))
                } ?: println("WTF $tagToLog:$messageToLog") // anonLogger.log(Level.SEVERE, messageToLog, tagToLog)
            }
        }.let { }
    }
}

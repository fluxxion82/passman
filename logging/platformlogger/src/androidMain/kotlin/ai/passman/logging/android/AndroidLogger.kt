package ai.passman.logging.android

import android.util.Log as AndroidLog
import ai.passman.logging.Logger

object AndroidLogger : Logger {

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
                    AndroidLog.v(tagToLog, messageToLog, it)
                } ?: AndroidLog.v(tagToLog, messageToLog)
            }
            Logger.Priority.INFO -> {
                throwable?.let {
                    AndroidLog.i(tagToLog, messageToLog, it)
                } ?: AndroidLog.i(tagToLog, messageToLog)
            }
            Logger.Priority.DEBUG -> {
                throwable?.let {
                    AndroidLog.d(tagToLog, messageToLog, it)
                } ?: AndroidLog.d(tagToLog, messageToLog)
            }
            Logger.Priority.WARNING -> {
                throwable?.let {
                    if (message == null) {
                        AndroidLog.w(tagToLog, it)
                    } else {
                        AndroidLog.w(tagToLog, messageToLog, it)
                    }
                } ?: AndroidLog.w(tagToLog, messageToLog)
            }
            Logger.Priority.ERROR -> {
                throwable?.let {
                    AndroidLog.e(tagToLog, messageToLog, it)
                } ?: AndroidLog.e(tagToLog, messageToLog)
            }
            Logger.Priority.WTF -> {
                throwable?.let {
                    if (message == null) {
                        AndroidLog.wtf(tagToLog, it)
                    } else {
                        AndroidLog.wtf(tagToLog, messageToLog, it)
                    }
                } ?: AndroidLog.wtf(tagToLog, messageToLog)
            }
        }.let { }
    }
}

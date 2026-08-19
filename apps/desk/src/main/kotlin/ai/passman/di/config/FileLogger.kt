package ai.passman.di.config

import ai.passman.repo.Platform
import ai.passman.logging.Logger
import ai.passman.domain.base.CoroutineScopeFacade
import ai.passman.domain.identification.model.DeviceInfo
import ai.passman.domain.initialization.models.AppInformation
import kotlinx.coroutines.launch
import kotlin.time.Clock
import kotlinx.datetime.LocalDate
import kotlinx.datetime.format
import kotlinx.datetime.format.DateTimeComponents
import kotlinx.datetime.format.char
import java.io.File

class FileLogger(
    private val appInformation: AppInformation,
    private val platform: Platform,
    private val deviceInfo: DeviceInfo,
    private val coroutineScopeFacade: CoroutineScopeFacade,
): Logger {
    private val nameFormat = DateTimeComponents.Format {
        date(LocalDate.Formats.ISO_BASIC)
        char('-'); hour(); char(' '); minute(); char(' '); second();
    }
//    private val logFormat = DateTimeComponents.Format {
//        date(LocalDate.Formats.ISO_BASIC)
//        char('-'); hour(); char(' '); minute(); char(' '); second();
//    }
    private val logHome = File("${platform.getLocalPath()}${File.separator}logs")
    private val logFile = File(logHome, "${Clock.System.now().format(nameFormat)}-logs.txt")
    init {
        if (!logHome.exists()) {
            logHome.mkdirs()
        }
        if (!logFile.exists()) {
            logFile.createNewFile()
        }
    }
    override fun log(
        priority: Logger.Priority,
        explicitTag: String?,
        inferredTag: String,
        message: String?,
        throwable: Throwable?,
        properties: Map<String, String>?
    ) {
        val logThread = Thread.currentThread().toString()

        coroutineScopeFacade.globalScope.launch {
            val logMessage = getDefaultMessages()
            logMessage.putAll(properties.orEmpty())
            logMessage[MESSAGE] = message.orEmpty()
            logMessage[THREAD] = logThread
            logMessage[TAG] = explicitTag ?: inferredTag
            throwable?.let {
                logMessage[STACK_TRACE] = it.stackTrace.joinToString { "\n" }
            }
            logMessage[LOG_LEVEL] = priority.name

            val log = buildString {
                appendLine("${Clock.System.now().format(DateTimeComponents.Formats.ISO_DATE_TIME_OFFSET)} ${priority.name} ${explicitTag ?: inferredTag}: $message, ${properties.orEmpty()}")
                throwable?.let {
                    appendLine(
                        it.stackTrace.joinToString { "\n" }
                    )
                }
            }

            logFile.appendText("$log\n")
        }
    }

    @Synchronized
    private fun getDefaultMessages(): MutableMap<String, String> {
        val messages = mutableMapOf<String, String>()
        messages[TIMESTAMP] = Clock.System.now().toString()
        messages[APP_VERSION] = "${appInformation.version.name}_${appInformation.version.build}-" +
                "${appInformation.version.additionalInfo}_${appInformation.versionCode}"
        messages[DEVICE_TYPE] = "${deviceInfo.manufacturer} ${deviceInfo.model}"
        messages[ANDROID_VERSION] = deviceInfo.frameworkApiVersion.toString()

        return messages
    }

    companion object {
        private const val TIMESTAMP = "@timestamp"
        private const val MESSAGE = "message"
        private const val LOG_LEVEL = "loglevel"
        private const val USER_EMAIL = "email"
        private const val ANDROID_VERSION = "android_version"
        private const val THREAD = "thread"
        private const val TAG = "tag"
        private const val APP_VERSION = "app_version"
        private const val DEVICE_TYPE = "android_device"
        private const val STACK_TRACE = "stacktrace"
    }
}

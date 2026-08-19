package ai.passman.logging

private const val CALL_STACK_INDEX = 3
private val ANONYMOUS_CLASS_PATTERN = Regex("(\\$\\d+)+$")

@Suppress("ThrowingExceptionsWithoutMessageOrCause")
internal actual fun inferTag(): String =
    Throwable().stackTrace
        .getOrElse(CALL_STACK_INDEX) {
            throw IllegalStateException("Synthetic stacktrace didn't have enough elements")
        }
        .let {
            val className = ANONYMOUS_CLASS_PATTERN.replace(it.className, "")
            "${className.substringAfterLast(".")}#${it.methodName}:${it.lineNumber}"
        }

package ai.passman.viewmodel.base

internal fun buildDeleteMessage(success: Int, failed: Int, total: Int, noun: String): String {
    val plural = if (total == 1) noun else "${noun}s"
    return when {
        failed == 0 -> "Deleted $success $plural"
        success == 0 -> "Failed to delete $failed $plural"
        else -> "Deleted $success of $total $plural; $failed failed"
    }
}

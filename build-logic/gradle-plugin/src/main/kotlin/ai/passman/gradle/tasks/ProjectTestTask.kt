package ai.passman.gradle.tasks

import org.gradle.api.DefaultTask

open class ProjectTestTask : DefaultTask() {
    init {
        group = "ci"
        description = "Runs tests for all modules"
    }
}

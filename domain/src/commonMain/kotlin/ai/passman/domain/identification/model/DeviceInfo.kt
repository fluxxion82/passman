package ai.passman.domain.identification.model

data class DeviceInfo(
    val manufacturer: String,
    val model: String,
    val frameworkApiVersion: Int
)

package ai.passman.repo

import java.io.File

expect fun createNewFileWithAppendedName(filePath: String, appendName: String): File

package ai.passman.repo

import java.io.File

actual fun createNewFileWithAppendedName(filePath: String, appendName: String): File {
    val file = File(filePath)
    if (!file.exists()) {
        throw IllegalArgumentException("File does not exist: $filePath")
    }

    val parentDir = file.parent ?: throw IllegalArgumentException("No parent directory found for the file: $filePath")
    val fileName = file.nameWithoutExtension
    val fileExtension = file.extension

    val newFileName = "${fileName}_${appendName}.$fileExtension"
    val newFilePath = "$parentDir${File.separator}$newFileName"

    val newFile = File(newFilePath)
    newFile.createNewFile()

    return newFile
}

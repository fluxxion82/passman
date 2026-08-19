package ai.passman.repo

import android.os.Environment
import java.io.File

actual fun createNewFileWithAppendedName(filePath: String, appendName: String): File {
    val file = File(filePath)
    if (!file.exists()) {
        throw IllegalArgumentException("File does not exist: $filePath")
    }

    val fileName = file.nameWithoutExtension
    val fileExtension = file.extension

    val newFileName = "${fileName}_${appendName}.$fileExtension"
    val newFilePath = "${Environment.getExternalStorageDirectory()}/$newFileName"

    val newFile = File(newFilePath)
    newFile.createNewFile()

    return newFile
}

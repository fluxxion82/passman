package ai.passman.repo

import java.io.File

class DesktopPlatform : Platform() {
    override fun getLocalPath(): String {
        val home = (System.getenv("APPDATA") ?: System.getProperty("user.home")) +
            File.separator + DesktopProfile.dataDirName
        val homeFile = File(home)
        if (!homeFile.exists()) {
            homeFile.mkdirs()
        }

        return home
    }
}

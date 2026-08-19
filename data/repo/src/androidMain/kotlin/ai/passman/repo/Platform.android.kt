package ai.passman.repo

import android.content.Context

class AndroidPlatform(val context: Context) : Platform() {
    override fun getLocalPath(): String {
        return context.filesDir.path
    }
}

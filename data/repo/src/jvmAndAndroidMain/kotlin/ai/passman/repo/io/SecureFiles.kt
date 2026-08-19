package ai.passman.repo.io

import java.io.File

/**
 * Best-effort owner-only file/dir permissions for sensitive material (vault DB, keystores, hybrid
 * key). On desktop/POSIX this is the difference between 0644 and 0600; on Android app-private storage
 * is already isolated so these calls are harmless no-ops, and on Windows they degrade gracefully.
 */
object SecureFiles {
    /** Restrict [file] to owner read/write only (~0600). */
    fun ownerOnly(file: File) {
        file.setReadable(false, false)
        file.setReadable(true, true)
        file.setWritable(false, false)
        file.setWritable(true, true)
        file.setExecutable(false, false)
    }

    /** Restrict [dir] to owner read/write/traverse only (~0700). */
    fun ownerOnlyDir(dir: File) {
        dir.setReadable(false, false)
        dir.setReadable(true, true)
        dir.setWritable(false, false)
        dir.setWritable(true, true)
        dir.setExecutable(false, false)
        dir.setExecutable(true, true)
    }
}

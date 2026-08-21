package ai.passman.repo.repositories

import ai.passman.domain.base.CoroutinesContextFacade
import ai.passman.domain.connectivity.model.SyncOps
import ai.passman.domain.settings.model.PreservedCopy
import ai.passman.domain.settings.repository.PreservedCopyRepository
import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences
import ai.passman.logging.KLogger
import ai.passman.platform.transfer.DirectoryBundler
import ai.passman.repo.Platform
import java.io.File
import kotlinx.coroutines.withContext

/**
 * Reads the conflict stores beside the artifact directories sync unbundles into.
 *
 * Both stores are plain sibling directories — `pgp/<user>.conflicts`, `keystore/<user>.conflicts` —
 * holding one file per displaced version. Sibling rather than child so an outbound bundle, which
 * walks every descendant of the artifact directory, cannot ship someone's secret ring to a peer.
 */
internal class LocalPreservedCopyRepository(
    private val platform: Platform,
    private val userPreferences: UserPreferences,
    private val coroutinesContextFacade: CoroutinesContextFacade,
) : PreservedCopyRepository {

    override suspend fun list(): List<PreservedCopy> = withContext(coroutinesContextFacade.io) {
        val user = loggedInUser() ?: return@withContext emptyList()
        ARTIFACTS.flatMap { artifact ->
            val directory = artifactDirectory(artifact, user) ?: return@flatMap emptyList()
            DirectoryBundler.preservedCopies(directory).map { file ->
                PreservedCopy(
                    artifact = artifact,
                    id = file.name,
                    originalName = DirectoryBundler.originalPathOf(file),
                    sizeBytes = file.length(),
                    modifiedAt = file.lastModified(),
                )
            }
        }.sortedByDescending { it.modifiedAt }
    }

    override suspend fun restore(copy: PreservedCopy): Boolean = withContext(coroutinesContextFacade.io) {
        val user = loggedInUser() ?: return@withContext false
        val directory = artifactDirectory(copy.artifact, user) ?: return@withContext false
        val file = resolveInStore(copy, directory) ?: return@withContext false
        // Where it goes is read back off the file, never from copy.originalName. That field exists to
        // be displayed; trusting it would let whatever populated it choose a write destination.
        runCatching { DirectoryBundler.restorePreserved(file, directory) }
            .onFailure { KLogger.e(it) { "failed to restore preserved copy" } }
            .getOrDefault(false)
    }

    override suspend fun delete(copy: PreservedCopy): Boolean = withContext(coroutinesContextFacade.io) {
        val user = loggedInUser() ?: return@withContext false
        val directory = artifactDirectory(copy.artifact, user) ?: return@withContext false
        val file = resolveInStore(copy, directory) ?: return@withContext false
        file.delete()
    }

    override suspend fun pathOf(copy: PreservedCopy): String? = withContext(coroutinesContextFacade.io) {
        val user = loggedInUser() ?: return@withContext null
        val directory = artifactDirectory(copy.artifact, user) ?: return@withContext null
        resolveInStore(copy, directory)?.path
    }

    private suspend fun loggedInUser(): String? = (userPreferences.getUser() as? AppUser.LoggedIn)?.userName

    private fun artifactDirectory(artifact: String, user: String): File? = when (artifact) {
        SyncOps.PGP -> File("${platform.getLocalPath()}${File.separator}pgp${File.separator}$user")
        SyncOps.KEYSTORE -> File("${platform.getLocalPath()}${File.separator}keystore${File.separator}$user")
        // An unrecognised artifact resolves to nothing rather than to a guess. Same reasoning as
        // SyncLogEntry keeping its artifact a plain String: an older or newer build's value must
        // land somewhere harmless instead of throwing or being coerced into the wrong directory.
        else -> null
    }

    /**
     * The file [copy] names, but only if it really is a direct child of that store.
     *
     * [PreservedCopy.id] is a string that arrives back from a caller and gets turned into a path, so
     * it is checked like any other untrusted path input: no separators, no traversal, and the
     * resolved parent must be the store itself. Nothing upstream is supposed to send anything else —
     * which is exactly why it is worth confirming, since this resolves to files that get deleted and
     * to paths that get written.
     */
    private fun resolveInStore(copy: PreservedCopy, directory: File): File? {
        val id = copy.id
        if (id.isEmpty() || id == "." || id == ".." || id.contains('/') || id.contains('\\')) return null
        val store = DirectoryBundler.conflictStore(directory)
        val file = File(store, id)
        if (file.canonicalFile.parentFile != store.canonicalFile) return null
        return file.takeIf { it.isFile }
    }

    private companion object {
        val ARTIFACTS = listOf(SyncOps.PGP, SyncOps.KEYSTORE)
    }
}

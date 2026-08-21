package ai.passman.domain.settings.repository

import ai.passman.domain.settings.model.PreservedCopy

/**
 * Reaches the versions sync displaced, so they can be listed, put back, exported, or deleted.
 *
 * Deleting is as much a part of this contract as restoring. Preserved copies are secret key material
 * that no listing shows and no other screen can remove; a passphrase rotated *because it leaked*
 * would otherwise keep guarding live private bytes on disk forever, with nothing in the app able to
 * get rid of them.
 */
interface PreservedCopyRepository {

    /** Every displaced version still held, newest first. Empty when there are none. */
    suspend fun list(): List<PreservedCopy>

    /**
     * Puts [copy] back at the path it was displaced from, preserving whatever is live there now.
     *
     * The copy stops being a preserved copy: undoing a sync must not destroy the version the sync
     * installed, so the two swap places rather than one overwriting the other.
     */
    suspend fun restore(copy: PreservedCopy): Boolean

    /** Permanently deletes [copy]. There is no undo, which is the point of it. */
    suspend fun delete(copy: PreservedCopy): Boolean

    /** Filesystem path of [copy], for handing to the platform share/save flow. Null if it is gone. */
    suspend fun pathOf(copy: PreservedCopy): String?
}

package ai.passman.domain.connectivity

import ai.passman.domain.user.models.AppUser
import ai.passman.domain.user.repository.UserPreferences

/**
 * Who a pairing ceremony belongs to: the account that started it, and the session that answer was
 * given in.
 *
 * A ceremony is account material, not device material. The bundle we push to the peer is the
 * identity in `keystore/<user>/`, and what comes back is pinned into that account's trusted-device
 * store — the mTLS SPKI pin and PQ public keys the receive-side authorizer matches inbound sync
 * against. So a confirmation is only ever allowed to commit under the account that ran the
 * ceremony; anything else hands one account trust in a device only another account ever attested
 * to.
 *
 * Both halves are compared, never either alone — the same pair
 * `LocalTrustedDevicesRepository` guards its own writes on, for the same two reasons:
 *
 * - the **session** alone misses an account switch that reuses it. `LogoutUser` reissues the
 *   session through [UserPreferences.clear], so a session change means a logout interleaved; but a
 *   `LoginUser` with no logout in between leaves it untouched while the account moves.
 * - the **account** alone misses a logout and a log back in as the same user. The session id is new
 *   then, and a ceremony begun before that logout has provenance in a login that no longer exists.
 *
 * [current] reads the account from [UserPreferences.getUser], which is *not* a trustworthy answer
 * to "is anyone signed in" — `LocalUserPreferences` keeps the user name across a logout so the
 * login screen can prefill it. That is fine here and only here: this type is compared against
 * another sample of itself, never consulted for signed-in-ness, and the reissued session id catches
 * the logout that the surviving name hides. Whether a write is allowed at all stays the store's
 * decision, and it resolves the account from the login events instead.
 */
data class PairingOwner(val account: String?, val session: String) {
    companion object {
        /** The account and session as they stand right now. Null [account] means nobody is signed in. */
        suspend fun current(userPreferences: UserPreferences): PairingOwner {
            val account = when (val user = userPreferences.getUser()) {
                is AppUser.LoggedIn -> user.userName
                is AppUser.AccountCreated -> user.userName
                AppUser.Anonymous -> null
            }
            return PairingOwner(account = account, session = userPreferences.getSessionId())
        }
    }
}

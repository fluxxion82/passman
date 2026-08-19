package ai.passman.design.pass

import ai.passman.domain.password.model.EntryActivity
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * [activityKindLabel] is tested directly rather than through [EntryHistorySection] because the
 * behaviour that matters here — an unrecognised [EntryActivity.kind] renders a label instead of
 * crashing or vanishing — is a property of the mapping function itself, not of Compose rendering it.
 */
class EntryExtrasTest {

    @Test
    fun `the two kinds this build writes map to their own labels`() {
        assertEquals("Created", activityKindLabel(EntryActivity.KIND_CREATED))
        assertEquals("Edited", activityKindLabel(EntryActivity.KIND_EDITED))
    }

    @Test
    fun `an unrecognised kind renders a generic label instead of throwing`() {
        // Stands in for a kind a future build wrote and this one has never heard of. The
        // requirement is that this returns rather than throws — the `when` has no exhaustive
        // match to fall out of, on purpose (see EntryActivity's KDoc on why `kind` is a String).
        assertEquals("Changed", activityKindLabel("totp-viewed"))
    }
}

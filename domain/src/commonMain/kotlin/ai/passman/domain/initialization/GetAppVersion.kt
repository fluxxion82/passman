package ai.passman.domain.initialization

import ai.passman.domain.base.Usecase
import ai.passman.domain.initialization.models.AppInformation

/**
 * The one-line build identity shown under the settings list.
 *
 * The build number is part of it deliberately: the version name is bumped per release, while every
 * build handed to a tester between releases shares it, and "which version are you on" is only ever
 * asked when those builds differ. The debug marker is here for the same reason — on desktop, debug
 * and prod are separate installs with separate vaults, and the two look identical once running.
 */
class GetAppVersion(
    private val appInformation: AppInformation,
) : Usecase<Unit, String> {

    override suspend fun invoke(param: Unit): String {
        // The "v" rides on the name, not on the line: a build with no version name would
        // otherwise render as a bare "v (12)".
        val name = appInformation.version.name.takeIf { it.isNotBlank() }?.let { "v$it " }
        val build = "${name.orEmpty()}(${appInformation.versionCode})"

        return if (appInformation.debug) "$build · debug" else build
    }
}

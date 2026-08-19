import org.jetbrains.compose.desktop.application.dsl.TargetFormat

plugins {
    kotlin("jvm")
    alias(libs.plugins.jetbrains.compose)
    alias(libs.plugins.compose.compiler)
}

group = "ai.passman"
version = "1.0.3"

// Build variants, in the spirit of Android build types. `src/debug` and `src/prod` each supply
// `ai.passman.di.buildVariantModule`; exactly one is compiled into the app, so the profile is a
// compile-time fact rather than something a launcher can get wrong. Debug and prod are fully
// isolated (separate data dir, prefs node, and credential-store key), which is why this must not
// depend on how the app was started.
//
//   ./gradlew :apps:desk:run                            debug (default)
//   ./gradlew :apps:desk:packageDmg -Ppassman.variant=prod
val buildVariant = providers.gradleProperty("passman.variant").getOrElse("debug")
require(buildVariant == "debug" || buildVariant == "prod") {
    "passman.variant must be 'debug' or 'prod', got '$buildVariant'"
}
kotlin.sourceSets["main"].kotlin.srcDir("src/$buildVariant/kotlin")

// macOS signing & notarization credentials — never commit these.
//
// Set in ~/.gradle/gradle.properties (preferred) or as env vars:
//   passmanAppleId               (or env PASSMAN_APPLE_ID)
//   passmanAppleTeamId           (or env PASSMAN_APPLE_TEAM_ID)
//   passmanNotarizationPassword  (or env PASSMAN_NOTARIZATION_PASSWORD)  // app-specific password
//   passmanSigningIdentity       (or env PASSMAN_SIGNING_IDENTITY)       // e.g. "Developer ID Application: …"
//   passmanSigningKeychain       (or env PASSMAN_SIGNING_KEYCHAIN)       // optional, defaults to /Library/Keychains/System.keychain
//
// Missing values cause the corresponding block to be skipped, so unsigned local builds still work.
val appleId               = providers.gradleProperty("passmanAppleId")
    .orElse(providers.environmentVariable("PASSMAN_APPLE_ID"))
val appleTeamId           = providers.gradleProperty("passmanAppleTeamId")
    .orElse(providers.environmentVariable("PASSMAN_APPLE_TEAM_ID"))
val notarizationPassword  = providers.gradleProperty("passmanNotarizationPassword")
    .orElse(providers.environmentVariable("PASSMAN_NOTARIZATION_PASSWORD"))
val signingIdentity       = providers.gradleProperty("passmanSigningIdentity")
    .orElse(providers.environmentVariable("PASSMAN_SIGNING_IDENTITY"))
val signingKeychain       = providers.gradleProperty("passmanSigningKeychain")
    .orElse(providers.environmentVariable("PASSMAN_SIGNING_KEYCHAIN"))
    .orElse("/Library/Keychains/System.keychain")

val signingIdentityValue       = signingIdentity.orNull?.takeIf { it.isNotBlank() }
val appleIdValue               = appleId.orNull?.takeIf { it.isNotBlank() }
val appleTeamIdValue           = appleTeamId.orNull?.takeIf { it.isNotBlank() }
val notarizationPasswordValue  = notarizationPassword.orNull?.takeIf { it.isNotBlank() }

compose.desktop {
    application {
        mainClass = "ai.passman.PassManKt"
        nativeDistributions {
            targetFormats(TargetFormat.Dmg, TargetFormat.Msi, TargetFormat.Deb)
            packageName = "PassMan"
            packageVersion = "1.0.3"

            windows {
                iconFile.set(project.file("src/main/resources/icons/icon.ico"))
            }
            linux {
                iconFile.set(project.file("src/main/resources/icons/ic_launcher.png"))
            }
            macOS {
                iconFile.set(project.file("src/main/resources/icons/icon.icns"))
                bundleID = "ai.passman"

                if (signingIdentityValue != null) {
                    signing {
                        sign.set(true)
                        identity.set(signingIdentityValue)
                        keychain.set(signingKeychain)
                    }
                } else {
                    logger.warn(
                        "[apps:desk] passmanSigningIdentity not set — macOS code signing disabled. " +
                            "Set passmanSigningIdentity in ~/.gradle/gradle.properties to enable."
                    )
                }

                if (appleIdValue != null && appleTeamIdValue != null && notarizationPasswordValue != null) {
                    notarization {
                        appleID.set(appleIdValue)
                        password.set(notarizationPasswordValue)
                        teamID.set(appleTeamIdValue)
                    }
                } else {
                    logger.warn(
                        "[apps:desk] passmanAppleId / passmanAppleTeamId / passmanNotarizationPassword missing — " +
                            "macOS notarization disabled."
                    )
                }
            }
        }

        // ProGuard is disabled because BouncyCastle ships as a signed JCE provider:
        // the JVM verifies its jar signature when Security.insertProviderAt() runs,
        // and ProGuard's class writer doesn't reproduce byte-identical output even
        // for -kept classes, so JCE rejects the repackaged provider with
        // "SHA-256 digest error". Use `:apps:desk:packageDmg` + `notarizeDmg`.
        // proguard-rules.pro is still present in case we drop BC's JCE registration later.
        buildTypes.release.proguard {
            isEnabled.set(false)
        }
    }
}

dependencies {
    implementation(compose.desktop.currentOs)
    implementation(project(":domain"))
    implementation(project(":data:pgp"))
    implementation(project(":data:local:platform"))
    implementation(project(":logging:logger"))
    implementation(project(":logging:platformlogger"))
    implementation(project(":presentation:design"))
    implementation(project(":presentation:screens"))
    implementation(project(":presentation:viewmodel"))
    implementation(project(":data:repo"))

    implementation(libs.koin.core)
    implementation(libs.koin.compose)

    implementation(libs.kotlinx.datetime)

    testImplementation(libs.bundles.test.jvm)
}

tasks.test {
    useJUnit()
}

// A packaged distribution must never carry the debug variant: it would point real users at the
// debug data dir and prefs node, and register log sinks that write account names and vault paths
// to disk. Fail the build rather than produce that artifact.
listOf(
    "package",
    "packageDmg",
    "packageMsi",
    "packageDeb",
    "packageDistributionForCurrentOS",
    "packageReleaseDmg",
    "packageReleaseMsi",
    "packageReleaseDeb",
    "packageReleaseDistributionForCurrentOS",
    "createDistributable",
    "createReleaseDistributable",
).forEach { taskName ->
    tasks.matching { it.name == taskName }.configureEach {
        doFirst {
            check(buildVariant == "prod") {
                "$taskName packages the app for distribution and requires -Ppassman.variant=prod " +
                    "(current variant: $buildVariant)"
            }
        }
    }
}

plugins {
    id("passman.application")
    alias(libs.plugins.compose.compiler)
}

// Android release signing — never commit the keystore or these credentials.
//
// Android refuses to install an unsigned APK. Debug builds are signed automatically with
// ~/.android/debug.keystore; release builds have no default, so without this block
// assembleRelease emits droid-release-unsigned.apk, which cannot be installed, tested or
// uploaded.
//
// Set in ~/.gradle/gradle.properties (preferred) or as env vars:
//   passmanReleaseStoreFile      (or env PASSMAN_RELEASE_STORE_FILE)      // absolute path
//   passmanReleaseStorePassword  (or env PASSMAN_RELEASE_STORE_PASSWORD)
//   passmanReleaseKeyAlias       (or env PASSMAN_RELEASE_KEY_ALIAS)
//   passmanReleaseKeyPassword    (or env PASSMAN_RELEASE_KEY_PASSWORD)
//
// To create the keystore (keep it OUTSIDE this repo and outside ~/passman):
//
//   keytool -genkeypair -v \
//     -keystore ~/keys/passman-release.jks \
//     -alias passman -keyalg RSA -keysize 4096 -validity 10000 \
//     -storetype PKCS12
//
// Do NOT reuse ~/passman/keystore/ster/ster.pfx. That is the desktop app's live data
// directory: the app writes to it, the k2k sync feature transfers it between devices, and
// its password is the vault password. A release signing identity does not belong there.
//
// Missing values leave the release build unsigned rather than failing, so anyone without
// the key can still build.
val releaseStoreFile = providers.gradleProperty("passmanReleaseStoreFile")
    .orElse(providers.environmentVariable("PASSMAN_RELEASE_STORE_FILE"))
val releaseStorePassword = providers.gradleProperty("passmanReleaseStorePassword")
    .orElse(providers.environmentVariable("PASSMAN_RELEASE_STORE_PASSWORD"))
val releaseKeyAlias = providers.gradleProperty("passmanReleaseKeyAlias")
    .orElse(providers.environmentVariable("PASSMAN_RELEASE_KEY_ALIAS"))
val releaseKeyPassword = providers.gradleProperty("passmanReleaseKeyPassword")
    .orElse(providers.environmentVariable("PASSMAN_RELEASE_KEY_PASSWORD"))

// trim(): gradle.properties preserves trailing whitespace, which silently becomes part of
// the value. An untrimmed path fails with a confusing "Keystore file '<path>        ' not
// found", and an untrimmed password fails as a wrong password.
val releaseStoreFileValue = releaseStoreFile.orNull?.trim()?.takeIf { it.isNotEmpty() }
val releaseStorePasswordValue = releaseStorePassword.orNull?.trim()?.takeIf { it.isNotEmpty() }
val releaseKeyAliasValue = releaseKeyAlias.orNull?.trim()?.takeIf { it.isNotEmpty() }
val releaseKeyPasswordValue = releaseKeyPassword.orNull?.trim()?.takeIf { it.isNotEmpty() }

val hasReleaseSigning = releaseStoreFileValue != null &&
    releaseStorePasswordValue != null &&
    releaseKeyAliasValue != null &&
    releaseKeyPasswordValue != null

android {
    namespace = "ai.passman.android"
    compileSdk = libs.versions.compileSdk.get().toInt()

    defaultConfig {
        applicationId = "ai.passman.android"
        // Shared with apps/desk via gradle.properties so the two apps can't report different
        // versions of the same release. trim() for the same reason as the signing values above.
        versionCode = providers.gradleProperty("VERSION_CODE").get().trim().toInt()
        versionName = providers.gradleProperty("VERSION_NAME").get().trim()

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }

    if (hasReleaseSigning) {
        signingConfigs {
            create("release") {
                storeFile = file(releaseStoreFileValue!!)
                storePassword = releaseStorePasswordValue
                keyAlias = releaseKeyAliasValue
                keyPassword = releaseKeyPasswordValue
                // v1 is required for API < 24; minSdk here is 31, so v2/v3 alone suffice
                // and v1 only adds an extra signature block to every entry.
                enableV1Signing = false
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    } else {
        logger.warn(
            "[apps:droid] passmanRelease* properties not set — release builds will be " +
                "unsigned and cannot be installed. See the comment in this build file.",
        )
    }

    buildTypes {
        getByName("debug") {
            isDebuggable = true
            isMinifyEnabled = false
        }
        getByName("release") {
            isDebuggable = false
            isMinifyEnabled = true
            isShrinkResources = true
            if (hasReleaseSigning) {
                signingConfig = signingConfigs.getByName("release")
            }
            // AGP 9 dropped proguard-android.txt because it carries -dontoptimize.
            // Switching to the optimize variant means R8 now actually optimizes release
            // builds, which it previously did not. BouncyCastle registers its JCE provider
            // reflectively, so release behavior needs runtime verification on a device,
            // not just a successful assembleRelease. See proguard-rules.pro for the keeps.
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                File("proguard-rules.pro"),
            )
        }
    }

    packaging {
        resources {
            pickFirsts.addAll(
                listOf(
                    "org/bouncycastle/x509/CertPathReviewerMessages.properties",
                    "org/bouncycastle/x509/CertPathReviewerMessages_de.properties",
                    // BouncyCastle 1.85 added these to every artifact, so bcpg, bcprov,
                    // bcutil and bcpkix all collide. pickFirst rather than exclude: the
                    // BouncyCastle licence requires the notice to ship with the binary,
                    // so keep one copy instead of dropping all four.
                    "META-INF/LICENSE.md",
                    "META-INF/NOTICE.md"
                )
            )
            excludes.addAll(
                listOf(
                    "META-INF/kotlinx-serialization-runtime.kotlin_module",
                    "META-INF/INDEX.LIST",
                    "META-INF/io.netty.versions.properties",
                    "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
                )
            )

        }
    }
}

dependencies {
    implementation(project(":domain"))
    implementation(project(":data:local:platform"))
    implementation(project(":logging:logger"))
    implementation(project(":logging:platformlogger"))
    implementation(project(":presentation:viewmodel"))
    implementation(project(":presentation:design"))
    implementation(project(":data:repo"))
    implementation(project(":presentation:screens"))

    // Compose Multiplatform artifacts rather than androidx + compose-bom. These resolve to
    // the androidx artifacts on Android anyway, and using them keeps one version source
    // across the app and the shared presentation modules instead of two that can disagree.
    implementation(libs.compose.runtime)
    implementation(libs.compose.foundation)
    implementation(libs.compose.animation)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.ui.util)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.appcompat)
    implementation(libs.androidx.core.ktx)
    // Required by res/values/themes.xml, which parents on Theme.MaterialComponents.*.
    implementation(libs.google.material)

    // Previously injected by BaseAndroidPlugin into every Android module. That blanket
    // injection is gone, so the app declares what it actually uses: koin-android for
    // androidContext()/inject(), koin-core for the module DSL, coroutines for runBlocking.
    implementation(libs.koin.core)
    implementation(libs.koin.android)
    implementation(libs.kotlinx.coroutines.core)
}

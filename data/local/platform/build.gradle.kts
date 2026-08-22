plugins {
    id("passman.kmp.android")
    id("passman.test")
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    applyDefaultHierarchyTemplate()
    android {
        namespace = "ai.passman.android.platform"
        // src/androidMain/res holds strings.xml and xml/file_paths.xml
        androidResources { enable = true }
        // Recreates the host-test compilation that the legacy com.android.library +
        // androidTarget() setup produced implicitly. AGP 9 dropped defaultSourceSetName
        // from the builder, so the source set takes its default name and the sources live
        // in src/androidHostTest.
        withHostTest { }
        // EncryptedSharedPreferences and the Android Keystore both need a real device, so
        // the migration off androidx.security.crypto is covered by an instrumented test.
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }
        packaging {
            resources {
                excludes.add("META-INF/INDEX.LIST")
                excludes.add("META-INF/io.netty.versions.properties")
                excludes.add("META-INF/versions/9/OSGI-INF/MANIFEST.MF")
                // BouncyCastle 1.85 ships these in all four artifacts. pickFirst rather
                // than exclude: the licence requires the notice to ship with the binary.
                pickFirsts.add("META-INF/LICENSE.md")
                pickFirsts.add("META-INF/NOTICE.md")
            }
        }
    }
    jvm("desktop")
    iosArm64()
    iosSimulatorArm64()

    sourceSets {
        val commonMain = getByName("commonMain") {
            dependencies {
                implementation(project(":domain"))
                implementation(project(":logging:logger"))
                implementation(project(":data:crypto"))
                implementation(project(":data:cache"))
                implementation(project(":data:pgp"))
                implementation(project(":data:keystore"))
                implementation(project(":data:repo"))
                implementation(project(":k2k"))

                implementation(libs.kotlinx.coroutines.core)
                implementation(libs.kotlinx.datetime)
                implementation(libs.kotlinx.serialization)
                implementation(libs.koin.core)

                implementation(libs.bundles.multiplatform.settings)
            }
        }
        val jvmAndAndroidMain = create("jvmAndAndroidMain") {
            dependsOn(commonMain)
            dependencies {
                // No source here imports org.bouncycastle any more (the login-password KDF moved to
                // data:crypto), but KeyService resolves the provider by name at runtime —
                // KeyPairGenerator.getInstance("ECDH", "BC") — so BC must stay on the runtime classpath.
                implementation(libs.bundles.bouncycastle)
                // We use only MnemonicUtils, whose BIP39 word list is bundled in this JAR. Keeping the
                // dependency non-transitive avoids pulling Ethereum/KZG runtime components that are
                // unrelated to recovery phrases; Bouncy Castle is already declared above.
                implementation("org.web3j:crypto:${libs.versions.web3jCrypto.get()}") {
                    isTransitive = false
                }
                // MnemonicUtils delegates SHA-256 to this utility module; it also runs against
                // the Bouncy Castle dependency already declared above.
                implementation("org.web3j:utils:${libs.versions.web3jCrypto.get()}") {
                    isTransitive = false
                }
                // TOTP QR decode. Shared here because both platforms feed it plain ARGB pixel
                // arrays; only the image loading (BitmapFactory vs ImageIO) is per-platform.
                implementation(libs.zxing.core)
            }
        }
        val androidMain = getByName("androidMain") {
            dependsOn(jvmAndAndroidMain)
            dependencies {
                implementation(libs.koin.android)
                implementation(libs.bundles.bouncycastle)

                // AppCompatActivity is used by AndroidBioAuthService. This was previously
                // resolving transitively; declare it so it survives the convention-plugin
                // rewrite that removes blanket dependency injection.
                implementation(libs.androidx.appcompat)
                implementation(libs.androidx.biometric)
                // No exclude(org.bouncycastle) here: security-crypto's only transitive deps are
                // androidx.annotation, androidx.collection and tink-android. The exclusion this
                // replaced was inherited from the security-identity-credential declaration.
                implementation(libs.androidx.security.crypto)
            }
        }
        getByName("desktopMain") {
            dependsOn(jvmAndAndroidMain)
            dependencies {
                implementation(libs.bundles.bouncycastle)

                implementation(libs.credential.storage.jvm)
                implementation(libs.jna)
            }
        }
        getByName("desktopTest") {
            dependencies {
                implementation(libs.kotlin.test)
                // MapSettings, so the real LocalTrustedDevicesRepository can be driven against an
                // in-memory Settings store instead of a fake that re-implements its logic.
                implementation(libs.multiplatform.settings.test)
            }
        }
        getByName("androidDeviceTest") {
            dependencies {
                implementation(libs.kotlin.test)
                implementation(libs.androidx.test.core)
                implementation(libs.androidx.test.runner)
                implementation(libs.androidx.test.ext.junit)
                implementation(libs.androidx.security.crypto)
            }
        }
        val androidHostTest = getByName("androidHostTest") {
            dependencies {
                implementation(libs.androidx.arch.core.testing)
                // TestFacades.kt uses javax.inject.Inject; this was previously arriving
                // transitively.
                implementation(libs.javax.inject)
            }
        }
    }
}

// All @Test methods in this module's Android unit-test sources are currently commented out,
// so the test task would otherwise fail with "no tests discovered". Restore once any test is uncommented.
tasks.withType<Test>().configureEach {
    failOnNoDiscoveredTests = false
}

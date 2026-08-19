# Development

## Prerequisites

- JDK 17 (pinned via `JvmTarget.JVM_17` and `compileOptions` in `BaseKmmPlugin`).
- The `k2k` submodule checked out — `git clone --recurse-submodules`, or `git submodule update --init` after the fact. Configuration fails without it.
- No manual plugin publish step: `build-logic/` is wired in via `pluginManagement { includeBuild("build-logic") }`, so edits to convention plugins rebuild automatically on the next `./gradlew` invocation.

## Common commands

| Task | Command |
| --- | --- |
| Build everything | `./gradlew build` |
| Android app | `./gradlew :apps:droid:assembleDebug` |
| Desktop app (debug variant) | `./gradlew :apps:desk:run` |
| All JVM/Android tests across modules | `./gradlew projectTest` |
| Android lint across modules | `./gradlew projectLint` |
| Tests for one module / target | `./gradlew :domain:jvmTest` &nbsp;·&nbsp; `./gradlew :data:repo:testDebugUnitTest` |
| Single test class | `./gradlew :domain:jvmTest --tests "ai.passman.domain.crypto.DecryptDataTest"` |
| Single test method | `./gradlew :domain:jvmTest --tests "ai.passman.domain.crypto.DecryptDataTest.someMethod"` |
| Clean | `./gradlew clean` |

## Build variants

The desktop app has `debug` and `prod` variants, in the spirit of Android build types. `apps/desk/src/debug` and `apps/desk/src/prod` each supply `ai.passman.di.buildVariantModule`, and exactly one is compiled in — selected at configuration time by the `passman.variant` Gradle property, which defaults to `debug`.

```bash
./gradlew :apps:desk:run                                 # debug
./gradlew :apps:desk:packageDmg -Ppassman.variant=prod   # prod
```

The two are **fully isolated** and that isolation is the point — a developer build must never touch a real vault:

| | debug | prod |
| --- | --- | --- |
| data directory | `~/passman_debug` | `~/passman` |
| `java.util.prefs` node | `ai.passman.platform.debug` | `ai.passman.platform` |
| credential-store master key | `passmanMasterKey_debug` | `passmanMasterKey` |
| log sinks | console + file | **none** |

Prod registers no logger at all: `FileLogger` creates its output file during construction, and even warning and error messages can contain account names, vault paths, or provider text.

Because the variant is a compile-time fact rather than a runtime flag, there is no way to launch the app into the wrong profile — a plain main-class run configuration cannot miss a JVM argument and silently open the production vault. Packaging tasks (`packageDmg`, `packageMsi`, `packageDeb`, `createDistributable`, …) **fail** unless `-Ppassman.variant=prod`, so a debug build cannot be shipped.

Anything profile-dependent belongs on `DesktopProfile`, which is injected via Koin. Deriving it independently somewhere else is how a debug build ends up naming the production data directory.

Two source-level guards in `apps/desk/src/test/.../LoggingModuleTest.kt` pin this: prod must register no `Logger`, and debug must register both.

Run configurations for the common tasks ship in `.run/`, so the IDE picks them up on clone.

## Custom Gradle plugins

The included build at `build-logic/` registers four plugin IDs. Apply them via `plugins { id("…") }` in module build files — the catalog at `gradle/libs.versions.toml` supplies their versions and dependencies.

| Plugin ID | Applied to | What it does |
| --- | --- | --- |
| `passman.root` | Repo root only | Registers the `projectTest` and `projectLint` aggregator tasks below. |
| `passman-lib.kotlin-multi` | KMP library modules (`domain`, `data/*`, `presentation/viewmodel`, etc.) | Applies `kotlin-multiplatform`, pins JDK 17 + Kotlin language version 2.1, and adds coroutines + kotlin-test to `commonMain` / `commonTest`. |
| `passman-lib.android` | Android-library modules (`data/*`, `presentation/*`) | Applies `com.android.library` + `kotlin-android` + `kotlin-parcelize`, pulls SDK levels from the catalog, adds Koin and Android test deps, and wires `lintDebug` into the `projectLint` aggregator. |
| `passman-application` | Android app modules (`apps/droid`) | Applies `com.android.application` and auto-applies any `.pro` files under `proguard/`. |

### Aggregator tasks (registered by `passman.root`)

- **`./gradlew projectTest`** — walks every subproject and depends on every `Test`-typed task it finds. That covers KMP `jvmTest`, Android `testDebugUnitTest`, and any other JVM test tasks per module.
- **`./gradlew projectLint`** — depends on `lintDebug` in every Android-library module. Each `LibraryPlugin` application wires its module's `lintDebug` into this aggregator, so you don't have to enumerate them.

Both tasks are defined in `build-logic/gradle-plugin/src/main/kotlin/ai/passman/gradle/tasks/`.

## Module map

Layered, Clean-Architecture-style — each layer only depends downward.

```
apps/{droid,desk}, iosdi ─┐
presentation/screens      │
presentation/viewmodel ───┤
presentation/design       │
presentation/viewvo       │
                          ▼
       domain  ◄────── data/repo ◄── data/{crypto,pgp,keystore,cache,local/platform}
         ▲                              │
         └──────── logging/logger ──────┘
```

- **`apps/droid`, `apps/desk`** — Android and Compose-for-Desktop applications. Thin front-ends over the shared ViewModels.
- **`iosdi/`** — iOS DI module; the port is in progress.
- **`presentation/screens/`** — Compose screens shared by both apps.
- **`domain/`** — Pure KMP (`commonMain`, `jvm`, `js(IR)`, `iosArm64`, `iosSimulatorArm64`). Feature folders (`crypto/`, `keystore/`, `password/`, `pgp/`, `user/`, etc.) hold use-cases at the top level plus `repository/`, `persistence/`, `model/`, `exception/`, `service/` subpackages. Repository interfaces only — implementations live in `data/repo`.
- **`data/repo/`** — Implements `domain` repository contracts. Most logic in a shared `jvmAndAndroidMain` source set (`dependsOn(commonMain)`); `androidMain` and `desktopMain` both `dependsOn(jvmAndAndroidMain)`. BouncyCastle is JVM/Android-only and is pulled in at this layer.
- **`data/{crypto,pgp,keystore,cache,local/platform}/`** — Lower-level building blocks the repo layer composes. `cache` uses the same `jvmAndAndroidMain` trick.
- **`presentation/viewmodel/`** — Compose-runtime ViewModels via Koin (`koin-compose-viewmodel`) + `androidx.lifecycle.viewmodel`. `BaseViewModel` / `ViewModelScope` are `expect/actual` across `commonMain`/`androidMain`/`jvmMain`. **ViewModels depend on `domain` use-cases, never on `data/*`** — if you find yourself wanting to inject a repository, add a use-case in `domain` instead.
- **`presentation/design/`, `presentation/viewvo/`** — Shared Compose design system and view value objects.
- **`logging/{logger,platformlogger}`** — `expect/actual` logger with per-platform impls.
- **`build-logic/`** — The included build described above.
- **`k2k/`** — Submodule. LAN transfer library, Apache-2.0, developed separately because it is useful outside this project. Included into the build as `:k2k` via `project(":k2k").projectDir = file("k2k/k2k")`.

## Conventions and gotchas

- **Single package root:** everything lives under `ai.passman.*`. `PgpKeyType` pins short `@SerialName` discriminators and `LocalPgpPreferences` migrates pre-rename stored JSON — keep both if you touch them.
- **DI is Koin with `expect val` modules.** When adding a platform binding, update the relevant `*.android.kt` / `*.desktop.kt` / `*.ios.kt` actual.
- **KMP target sets differ between modules.** `domain` and `logging/logger` target JVM + JS(IR) + iOS; `data/*` and `presentation/viewmodel` skip JS and add `androidTarget()`. Don't add JS-incompatible deps to `domain`; don't add Android-only deps outside an `androidMain` / `jvmAndAndroidMain` source set.
- **`tasks.register("testClasses")`** appears as a no-op stub in several KMP module build files so the Android Gradle Plugin doesn't fail looking for it. Don't remove it.
- **No publishing.** Modules are consumed within this repo by path, never as Maven artifacts, so nothing needs to be published to build the apps. `LIBRARY_VERSION` and `GROUP` in `gradle.properties` still set each subproject's `version` and `group`.
- **Test fixtures never contain real keys.** PGP tests generate throwaway key rings at runtime (see `PgpClientTest.generateKeyRingFiles`). The committed `.asc` fixtures are disposable identities (`test@user.com`, `sterling`). Do not commit a personal key as a fixture, even a passphrase-protected one.
- **Release signing is external.** `apps/droid` reads `passmanRelease*` Gradle properties or `PASSMAN_RELEASE_*` environment variables; the keystore lives outside the repo and `.gitignore` blocks `*.jks` / `*.p12` / `*.pfx` / `*.keystore`.
- **Code style.** `PassmanCodestyle.xml` at the repo root is the IntelliJ scheme; `.editorconfig` enforces basics. `kotlin.code.style=official`.

## License

Contributions are accepted under the repository's [AGPL-3.0](../LICENSE). The `k2k` submodule is Apache-2.0 and keeps its own license.

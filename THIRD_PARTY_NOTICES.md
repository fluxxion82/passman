# Third-party notices

Passman itself is licensed under the [GNU Affero General Public License v3.0](LICENSE). Assets and
components bundled in this repository or in built artifacts carry their own licenses, listed here.

## Bundled assets

### Inter

`presentation/design/src/commonMain/composeResources/font/inter_regular.ttf`

Copyright 2020 The Inter Project Authors (https://github.com/rsms/inter), licensed under the
SIL Open Font License, Version 1.1. Full license text: [licenses/Inter-OFL.txt](licenses/Inter-OFL.txt).

The bundled file is a static instance (weight 400, optical size 14) cut from the Inter variable
font distributed by Google Fonts.

## Bundled submodule

### k2k

`k2k/` — LAN device-to-device transfer library, developed in its own repository at
https://github.com/fluxxion82/k2k and licensed under the Apache License 2.0. Its license text
ships with the submodule at `k2k/LICENSE`.

## Dependencies

Runtime and build dependencies are declared in `gradle/libs.versions.toml` and resolved from Maven
Central, Google's Maven repository, and the JetBrains Compose repository. They are not vendored
here; each is governed by its own license.

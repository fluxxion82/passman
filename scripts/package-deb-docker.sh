#!/usr/bin/env bash

set -euo pipefail

# Everything the build needs now lives in this repo — k2k is a submodule under k2k/, not a
# sibling checkout — so the repo root is what gets mounted.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
gradle_cache_dir="${GRADLE_USER_HOME:-${HOME}/.gradle}"
# Tagged for the image's contents, not the app version: the builder only changes when the
# Dockerfile does.
image_name="passman-deb-builder:jdk21"

# jpackage stamps the .deb with the architecture it runs on, so a native build on Apple Silicon
# produces an arm64 package that will not install on an x86_64 Linux desktop. Set
# PASSMAN_DEB_PLATFORM=linux/amd64 to cross-build through qemu — correct, but slow enough that a
# real amd64 machine or CI runner is the better answer for a release.
platform_args=()
if [[ -n "${PASSMAN_DEB_PLATFORM:-}" ]]; then
    platform_args=(--platform "${PASSMAN_DEB_PLATFORM}")
    image_name="${image_name}-${PASSMAN_DEB_PLATFORM//\//-}"
fi

mkdir -p "${gradle_cache_dir}"

# :Z grants the Fedora Docker daemon access to the bind-mounted source and
# Gradle cache when SELinux is enforcing.
docker build \
    ${platform_args[@]+"${platform_args[@]}"} \
    --tag "${image_name}" \
    --file "${repo_dir}/docker/linux-deb/Dockerfile" \
    "${repo_dir}/docker/linux-deb"

docker run --rm \
    ${platform_args[@]+"${platform_args[@]}"} \
    --user "$(id -u):$(id -g)" \
    --env HOME=/home/gradle \
    --env GRADLE_USER_HOME=/home/gradle/.gradle \
    --volume "${repo_dir}:/workspace:Z" \
    --volume "${gradle_cache_dir}:/home/gradle/.gradle:Z" \
    --workdir /workspace \
    "${image_name}" \
    ./gradlew --no-daemon -Ppassman.variant=prod :apps:desk:packageReleaseDeb

# packageReleaseDeb writes to binaries/main-release/, packageDeb to binaries/main/. Search both
# rather than hard-coding one, so a stale package from the other task path is still reported.
printf '\nInstaller output:\n'
find "${repo_dir}/apps/desk/build/compose/binaries" -type f -name '*.deb' -print

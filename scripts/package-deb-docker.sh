#!/usr/bin/env bash

set -euo pipefail

# The Gradle settings file resolves passmanShared and k2k as siblings of
# passmanClient, so mount the workspace root rather than passmanClient alone.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
client_dir="$(cd "${script_dir}/.." && pwd)"
workspace_dir="$(cd "${client_dir}/.." && pwd)"
gradle_cache_dir="${GRADLE_USER_HOME:-${HOME}/.gradle}"
image_name="passman-deb-builder:1.0.2"

mkdir -p "${gradle_cache_dir}"

# :Z grants the Fedora Docker daemon access to the bind-mounted source and
# Gradle cache when SELinux is enforcing.
docker build \
    --tag "${image_name}" \
    --file "${client_dir}/docker/linux-deb/Dockerfile" \
    "${client_dir}"

docker run --rm \
    --user "$(id -u):$(id -g)" \
    --env HOME=/home/gradle \
    --env GRADLE_USER_HOME=/home/gradle/.gradle \
    --volume "${workspace_dir}:/workspace:Z" \
    --volume "${gradle_cache_dir}:/home/gradle/.gradle:Z" \
    --workdir /workspace/passmanClient \
    "${image_name}" \
    ./gradlew --no-daemon :apps:desk:packageDeb

printf '\nInstaller output:\n'
find "${client_dir}/apps/desk/build/compose/binaries/main/deb" -maxdepth 1 -type f -name '*.deb' -print

FROM eclipse-temurin:21-jdk-jammy

# Compose Desktop delegates Linux installers to jpackage. Debian packaging needs
# these native tools; keeping them in the image avoids installing them on Fedora.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        dpkg \
        fakeroot \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /home/gradle/.gradle \
    && chmod -R a+rwx /home/gradle

WORKDIR /workspace

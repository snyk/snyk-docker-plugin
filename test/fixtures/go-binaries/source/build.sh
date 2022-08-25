#!/bin/sh
# This shell script can be used to generate the binaries that are located in the parent folder.
# Simply call this script with no arguments. Needs Docker to be installed.
# The binaries here are used for the symbol parser and the Go version extraction test.

set -eux

versions="1.13.15 1.16.15 1.18.5 1.19.0"
# let the user overwrite the versions to build.
if [ "$#" -gt 0 ]; then
    versions="$*"
fi;

for version in $versions; do 
    # the "latest" builds need an "alpine" tag (there's no "latest-alpine" tag).
    if [ "$version" = "latest" ]; then
        tag="alpine"
        version="latest"
    else
        tag="$version-alpine"
        version="go$version"
    fi
    docker build . \
        --platform=linux/amd64 \
        --build-arg GO_IMAGE_TAG=$tag \
        --build-arg GO_VERSION=$version \
        -t gotest:$version \

    id="$(docker create --platform=linux/amd64 gotest:$version)"
    docker cp "$id":/app/out/. ../
    docker rm -v "$id"
done

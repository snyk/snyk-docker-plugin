#! /bin/bash

set -ex

cd ~/snyk-docker-plugin/test/fixtures/go-binaries/source
./build.sh latest
echo "Running tests"

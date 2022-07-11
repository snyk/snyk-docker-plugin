#! /bin/bash

mkdir -p ~/go-test
cp -r test/go-binary-regression/. ~/go-test/
cd ~/go-test
echo "Building Docker image"
docker build -t gotest:latest .
id=$(docker create gotest:latest)
echo "Copying Go binary"
docker cp $id:/app/testgo ~/snyk-docker-plugin/test/fixtures/go-binaries/latest
docker rm -v $id
echo "Running tests"

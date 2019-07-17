#!/usr/bin/env bash
#
# A utility script to create images of a specified size.
# The script is called by pref.ts to create large
#  images for performance comparison tests

if [ -n "$1" ]; then
	pushd "$(dirname "$0")"
	echo creating fake dockerfile...
	echo FROM node:10.4.0>temp_fake_dockerfile
	echo COPY temp_fake_file.bin />>temp_fake_dockerfile
	echo creating fake file...
	dd if=/dev/zero of="$(dirname "$0")/temp_fake_file.bin" bs=1g count=$1
	echo creating image...
	docker build --no-cache -t fake-$1g -f temp_fake_dockerfile $(dirname "$0")
	echo removing fake dockerfile...
	rm temp_fake_dockerfile
	echo removing fake file...
	rm temp_fake_file.bin
	popd
fi

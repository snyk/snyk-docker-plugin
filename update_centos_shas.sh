#!/bin/bash

# Script to fetch latest SHA256 digests for CentOS stream images and update test file

set -e

echo "Fetching SHA256 digest for quay.io/centos/centos:stream9..."
STREAM9_SHA=$(docker manifest inspect --verbose quay.io/centos/centos:stream9 | jq -r '.[] | select(.Descriptor.platform.architecture == "amd64" and .Descriptor.platform.os == "linux") | .Descriptor.digest')

echo "Fetching SHA256 digest for quay.io/centos/centos:stream10..."
STREAM10_SHA=$(docker manifest inspect --verbose quay.io/centos/centos:stream10 | jq -r '.[] | select(.Descriptor.platform.architecture == "amd64" and .Descriptor.platform.os == "linux") | .Descriptor.digest')

echo "Stream 9 SHA: $STREAM9_SHA"
echo "Stream 10 SHA: $STREAM10_SHA"

# Validate we got proper SHA digests
if [[ ! $STREAM9_SHA =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "Error: Invalid stream9 SHA format: $STREAM9_SHA"
    exit 1
fi

if [[ ! $STREAM10_SHA =~ ^sha256:[a-f0-9]{64}$ ]]; then
    echo "Error: Invalid stream10 SHA format: $STREAM10_SHA"
    exit 1
fi

TEST_FILE="test/system/package-managers/rpm.spec.ts"

echo "Updating $TEST_FILE with new SHA digests..."

# Update line 28 (stream9 in afterAll cleanup)
sed -i.bak "28s|quay.io/centos/centos@sha256:[a-f0-9]*|quay.io/centos/centos@$STREAM9_SHA|" "$TEST_FILE"

# Update line 29 (stream10 in afterAll cleanup)  
sed -i.bak "29s|quay.io/centos/centos@sha256:[a-f0-9]*|quay.io/centos/centos@$STREAM10_SHA|" "$TEST_FILE"

# Update line 78 (stream9 in test)
sed -i.bak "78s|quay.io/centos/centos@sha256:[a-f0-9]*|quay.io/centos/centos@$STREAM9_SHA|" "$TEST_FILE"

# Update line 91 (stream10 in test)
sed -i.bak "91s|quay.io/centos/centos@sha256:[a-f0-9]*|quay.io/centos/centos@$STREAM10_SHA|" "$TEST_FILE"

# Remove backup file
rm "${TEST_FILE}.bak"

echo "Successfully updated $TEST_FILE with:"
echo "  Stream 9: $STREAM9_SHA"
echo "  Stream 10: $STREAM10_SHA"

echo ""
echo "Updated lines:"
echo "Line 28: $(sed -n '28p' "$TEST_FILE")"
echo "Line 29: $(sed -n '29p' "$TEST_FILE")"
echo "Line 78: $(sed -n '78p' "$TEST_FILE")"
echo "Line 91: $(sed -n '91p' "$TEST_FILE")"

echo ""
echo "Running RPM tests to update snapshots..."
npm run test-jest -- test/system/package-managers/rpm.spec.ts --updateSnapshot

echo ""
echo "SHA update and snapshot refresh completed successfully!"
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

SHA_FILE="test/fixtures/centos-shas.ts"

echo "Updating $SHA_FILE with new SHA digests..."

# Update the SHA file with new digests
cat > "$SHA_FILE" << EOF
// CentOS Stream SHA digests for quay.io/centos/centos images
// This file is automatically updated by the update_centos_shas.sh script
// Run \`npm run update-quay-tests\` to fetch the latest SHA digests

export const CENTOS_SHAS = {
  stream9:
    "$STREAM9_SHA",
  stream10:
    "$STREAM10_SHA",
} as const;
EOF

echo "Successfully updated $SHA_FILE with:"
echo "  Stream 9: $STREAM9_SHA"
echo "  Stream 10: $STREAM10_SHA"

echo ""
echo "Running RPM tests to update snapshots..."
npm run test-jest -- test/system/package-managers/rpm.spec.ts --updateSnapshot

echo ""
echo "SHA update and snapshot refresh completed successfully!"
#!/bin/bash
# This script is called by semantic-release during the prepare step
# to update the version constant before publishing to npm.

VERSION=$1

if [ -z "$VERSION" ]; then
  echo "Error: Version argument is required"
  exit 1
fi

cat > lib/version.ts << EOF
// This file is auto-generated during the release process.
// Do not edit manually.
export const PLUGIN_VERSION = "${VERSION}";
EOF

echo "Updated lib/version.ts with version ${VERSION}"


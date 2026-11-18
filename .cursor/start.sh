#!/usr/bin/env bash
set -euo pipefail

export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"
NODE_VERSION="$(tr -d 'v' < "$(dirname "$0")/../.nvmrc")"

if [ -s "$NVM_DIR/nvm.sh" ] && [ -d "${NVM_DIR}/versions/node/v${NODE_VERSION}/bin" ]; then
  # shellcheck disable=SC1091
  . "$NVM_DIR/nvm.sh"
  export PATH="${NVM_DIR}/versions/node/v${NODE_VERSION}/bin:${PATH}"
fi

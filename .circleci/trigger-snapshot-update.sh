#!/usr/bin/env bash
# Manually trigger the Jest snapshot-update jobs on CircleCI.
#
# The run_snapshot_update pipeline parameter cannot be set from the CircleCI UI;
# it must be passed via the API. This script does that for the current (or a
# given) branch.
#
# Usage:
#   CIRCLE_TOKEN=<personal-api-token> ./.circleci/trigger-snapshot-update.sh [branch]
#
# Get a token at: CircleCI -> User Settings -> Personal API Tokens.
set -euo pipefail

: "${CIRCLE_TOKEN:?Set CIRCLE_TOKEN to a CircleCI personal API token}"

branch="${1:-$(git rev-parse --abbrev-ref HEAD)}"
project="gh/snyk/snyk-docker-plugin"

echo "Triggering snapshot update on branch: ${branch}"
curl -fsS -X POST "https://circleci.com/api/v2/project/${project}/pipeline" \
  -H "Circle-Token: ${CIRCLE_TOKEN}" \
  -H 'Content-Type: application/json' \
  -d "{\"branch\":\"${branch}\",\"parameters\":{\"run_snapshot_update\":true}}"
echo

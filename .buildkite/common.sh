#!/bin/bash

set -e

if [ "$BUILDKITE_PULL_REQUEST" == "false" ]; then
    TARGET="$BUILDKITE_BRANCH"
else
    TARGET="$BUILDKITE_PULL_REQUEST"
fi
TARGET="${TARGET//\//_}"
BUILD="build-${BUILDKITE_BUILD_NUMBER}"
[ -n "$NIGHTLY" ] && BUILD=nightly-"$(date +%s)"

echo "env:"
echo "  SCION_MOUNT: /tmp/scion_out.$BUILDKITE_BUILD_NUMBER"
echo "  SCION_CNTR: scion_ci_$BUILDKITE_BUILD_NUMBER"
echo "  ARTIFACTS: buildkite.${BUILDKITE_ORGANIZATION_SLUG}.${TARGET}.${BUILD}"
echo "  BASE: $BASE"

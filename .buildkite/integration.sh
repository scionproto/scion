set -e

echo "- label: Integration Tests"
echo "  command:"
echo "  - docker pull \$SCION_IMG"
echo "  - ./tools/ci/integration_setup"
if [ "$BUILDKITE_BRANCH" == "master" ]; then
    echo "  - ./tools/ci/integration_run -a"
else
    echo "  - ./tools/ci/integration_run"
fi
echo "  timeout_in_minutes: 30"
echo "  concurrency: 1"
echo "  concurrency_group: \"integration-test\""

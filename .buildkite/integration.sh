set -e

echo "- label: Integration Tests"
echo "  command:"
echo "  - ./tools/ci/integration_setup"
if [ "$BUILDKITE_BRANCH" == "master" ]; then
    echo "  - ./tools/ci/integration_run -a"
else
    echo "  - ./tools/ci/integration_run"
fi
echo "  concurrency: 1"
echo "  concurrency_group: \"integration-test\""

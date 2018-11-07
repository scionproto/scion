for test in ./acceptance/*_acceptance; do
    echo "- label: ${test}"
    echo "  command:"
    echo "  - rm -f $SCION_MOUNT/logs/*"
    echo "  - docker pull $SCION_IMG"
    echo "  - ./tools/ci/run_acceptance $test"
    echo "  artifact_paths:"
    echo "  - \"artifacts.out/**/*\""
done

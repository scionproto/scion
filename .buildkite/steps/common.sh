log() {
    echo "$(date -u +"%F %T.%6N%z") $@"
}

prepare() {
    mkdir -p "artifacts.out"
    $BASE/scripts/clean_env &>> "$STEP_LOG"
    $BASE/scripts/registry_login &>> "$STEP_LOG"
    docker pull $SCION_IMG &>/dev/null
    mkdir -p $SCION_MOUNT
}

cleanup() {
    $BASE/scripts/pack_logs &>> "$STEP_LOG"
    local res=$?
    ./docker.sh stop &>> "$STEP_LOG"
    res=$((res+$?))
    $BASE/scripts/clean_env &>> "$STEP_LOG"
    res=$((res+$?))
    rm -r --interactive=never $SCION_MOUNT
    return $res
}

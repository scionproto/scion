log() {
    echo "$(date -u +"%F %T.%6N%z") $@"
}

prepare() {
    mkdir -p "artifacts.out"
    $BASE/scripts/clean_env &>> "$STEP_LOG"
    $BASE/scripts/registry_login &>> "$STEP_LOG"
    mkdir -p $SCION_MOUNT
    docker pull $SCION_IMG &>> "$STEP_LOG"
    softnet_stat_snapshot
}

cleanup() {
    detect_packet_loss_since_snapshot
    $BASE/scripts/pack_logs &>> "$STEP_LOG"
    local res=$?
    ./docker.sh stop &>> "$STEP_LOG"
    res=$((res+$?))
    $BASE/scripts/clean_env &>> "$STEP_LOG"
    res=$((res+$?))
    rm -r --interactive=never $SCION_MOUNT
    return $res
}

softnet_stat_snapshot() {
    # Collect packet loss info pre test execution
    cat /proc/net/softnet_stat > /tmp/snapshot_softnet_stat
}

detect_packet_loss_since_snapshot() {
    # Compare column2 of softnet_stat to detect kernel packet loss and print snapshot and current in case of packet loss
    if diff -q <(awk '{print $2}' /proc/net/softnet_stat) <(awk '{print $2}' /tmp/snapshot_softnet_stat); then
        echo "No Kernel Packet loss detected"
    else
        echo "Kernel Packet loss detected - /proc/net/softnet_stat column 2 differs from last snapshot"
        echo "Printing snapshot and current:"
        cat /tmp/snapshot_softnet_stat
        cat /proc/net/softnet_stat
    fi
}

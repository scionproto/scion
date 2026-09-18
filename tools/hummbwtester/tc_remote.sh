#!/bin/sh
# Run via sudo on an explicitly configured, dedicated experiment interface.
set -eu

action=$1
device=$2

root_kind() {
    tc qdisc show dev "$device" | awk '$1 == "qdisc" { print $2; exit }'
}

require_baseline() {
    kind=$(root_kind)
    if [ "$kind" != "noqueue" ]; then
        echo "refusing $action on $device: expected root qdisc noqueue, found ${kind:-none}" >&2
        exit 1
    fi
}

case "$action" in
    apply)
        [ "$#" -eq 5 ] || exit 2
        require_baseline
        tc qdisc replace dev "$device" root tbf rate "$3" burst "$4" limit "$5"
        ;;
    stats)
        [ "$#" -eq 2 ] || exit 2
        stats=$(tc -s qdisc show dev "$device")
        dropped=$(printf '%s\n' "$stats" | awk '/dropped/ {for (i = 1; i <= NF; i++) if ($i == "dropped") {print $(i + 1); exit}}')
        overlimits=$(printf '%s\n' "$stats" | awk '/overlimits/ {for (i = 1; i <= NF; i++) if ($i == "overlimits") {print $(i + 1); exit}}')
        [ -n "$dropped" ] && [ -n "$overlimits" ] || {
            echo "unable to parse TBF counters for $device" >&2
            exit 1
        }
        echo "HUMMBWTESTER_TC_STATS dev=$device dropped=$dropped overlimits=$overlimits"
        ;;
    cleanup)
        [ "$#" -eq 2 ] || exit 2
        tc qdisc del dev "$device" root
        require_baseline
        ;;
    *)
        echo "usage: $0 apply DEVICE RATE BURST LIMIT | stats DEVICE | cleanup DEVICE" >&2
        exit 2
        ;;
esac

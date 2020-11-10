#!/bin/sh
#
# [1] man 8 dhclient-script
# [2] man 8 dhclient
# [3] man 5 dhcp-options
#
# Variables used from dhclient:
#
# reason: why the script was invoked (see OPERATION in [1])
# new_www_server: see [3]
#
# dhclient: Install at /etc/dhcp/dhclient-exit-hooks.d/90-scion.sh
# dhcpcd:   Install at /usr/lib/dhcpcd/dhcpcd-hooks/90-scion.sh

LOG_FILE="/tmp/scion-dhclient.log"

HINT_DIRECTORY="/tmp/gen"

# 1: message to log
log() {
    echo "$(date "+%Y-%m-%dT%H:%M:%S") $1" >> "$LOG_FILE" 2>> "$LOG_FILE"
}


main() {
    if [ "$reason" != "BOUND" ] && [ "$reason" != "RENEW" ] && [ "$reason" != "REBOOT" ] ; then
        log "Ignoring call reason $reason"
        exit 0
    fi

    log "Adding bootstrapping hint for SCION at $new_www_server"
    echo "$new_www_server" > "$HINT_DIRECTORY"/10-dhclient.conf

    log "TODO: Notifying sciond"
}

main

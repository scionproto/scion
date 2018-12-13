# Acceptance tests common functions

ia_file() {
    echo ${1:?} | sed -e "s/:/_/g"
}

as_file() {
    ia_file ${1:?} | cut -d '-' -f 2
}

collect_metrics() {
    echo "Reading topology: ${1:?}"
    METRICS_DIR=${2:?}
    echo "Saving metrics in $METRICS_DIR"
    mkdir -p "$METRICS_DIR"

    local elems=$(jq '.BorderRouters | to_entries[] | .key' $1)
    for elem in $elems; do
        local ip="$(jq .BorderRouters[$elem].InternalAddrs.IPv4.PublicOverlay.Addr $1 | sed -e 's/^"//' -e 's/"$//')"
        curl "$ip:30442/metrics" -o "$METRICS_DIR/$(remove_quotes $elem)" -s -S
    done

    local elems=$(jq '.SIG | to_entries[] | .key' $1)
    for elem in $elems; do
        local ip="$(jq .SIG[$elem].Addrs.IPv4.Public.Addr $1 | sed -e 's/^"//' -e 's/"$//')"
        curl "$ip:30456/metrics" -o "$METRICS_DIR/$(remove_quotes $elem)" -s -S
    done
}

remove_quotes() {
    echo "${1:?}" | sed -e 's/^"//' -e 's/"$//'
}

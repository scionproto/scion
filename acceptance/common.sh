# Acceptance tests common functions

#######################################
# Converts ISD-AS representation to its file format
# Arguments:
#   ISD-AS
#######################################
ia_file() {
    echo ${1:?} | sed -e "s/:/_/g"
}

#######################################
# Converts ISD-AS representation to AS file format, i.e. removes the ISD
# Arguments:
#   ISD-AS
#######################################
as_file() {
    ia_file ${1:?} | cut -d '-' -f 2
}

#######################################
# Print docker container status
#######################################
docker_status() {
    log "Docker containers:"
    docker ps -a -s
}

#######################################
# Generic test_teardown, prints docker status and stops all containers
#######################################
test_teardown() {
    docker_status
    mkdir -p logs/docker
    ./tools/dc collect_logs scion logs/docker
    ./tools/dc down
}

#######################################
# Log: Echo with a timestamp
#######################################
log() {
    echo "$(date -u +"%F %T.%6N%z") $@"
}

#######################################
# Fail: Echo with a timestamp to stderr and exit with 1
#######################################
fail() {
    echo "$(date -u +'%F %T.%6N%z') $@" >&2
    exit 1
}

#######################################
# Return the ip of the container
# Arguments:
#   Name of the container
#######################################
container_ip() {
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1"
}

#######################################
# Collect docker compose logs into logs/docker
# Arguments:
#   The docker compose bash method to call.
#######################################
collect_docker_logs() {
    local cmd="${1:?"Missing cmd argument"}"
    local out_dir=logs/docker
    mkdir -p "$out_dir"
    for svc in $("$cmd" config --services); do
        "$cmd" logs $svc &> $out_dir/$svc.log
    done
}

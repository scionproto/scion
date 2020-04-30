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
    ./tools/dc collect_logs logs/docker
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
# Returns whether this script is running in docker
#######################################
is_running_in_docker() {
    cut -d: -f 3 /proc/1/cgroup | grep -q '^/docker/'
}

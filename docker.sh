#!/bin/bash

ORG=scionproto
branch=
build_dir=
image_tag=

get_params() {
    # If we're on a local branch, use that. If we're on a detached HEAD from a
    # remote branch, or from a bare rev id, use that instead.
    branch=$(LC_ALL=C git status | head -n1 |
    awk '/^On branch|HEAD detached at/ {print $NF}')
    build_dir="docker/_build/$branch"
    image_tag=$(echo "$branch" | tr '/' '.')
}

cmd_base() {
    set -e
    set -o pipefail
    get_params
    copy_tree
    docker_build "base"
    docker tag scion_base:latest "$ORG/scion_base:pending"
    touch docker/_build/scion_base.stamp
}

cmd_build() {
    set -e
    set -o pipefail
    get_params
    copy_tree
    docker_build
}

cmd_tester() {
    set -eo pipefail
    make -C docker/perapp base
    docker build -t "tester:latest" - < docker/Dockerfile.tester
}

copy_tree() {
    set -e
    set -o pipefail
    echo "Copying current working tree for Docker image"
    echo "============================================="
    mkdir -p "${build_dir:?}"
    # Just in case it's sitting there from a previous run
    rm -rf "${build_dir}/scion.git/"
    {
        git ls-files;
        git submodule --quiet foreach 'git ls-files | sed "s|^|$path/|"';
    } | rsync -a --files-from=- . "${build_dir}/scion.git/"
    echo
}

docker_build() {
    set -e
    set -o pipefail
    local suffix="$1"
    local image_name="scion${suffix:+_$suffix}"
    local conf_rel="docker/Dockerfile${suffix:+.$suffix}"
    local conf="${build_dir:?}/scion.git/$conf_rel"
    local tag="$image_name:${image_tag:?}"
    local log="$build_dir/build${suffix:+_$suffix}.log"
    [ -n "$suffix" ] || local build_args="--build-arg SCION_UID=$(id -u) --build-arg SCION_GID=$(id -g) --build-arg DOCKER_GID=$(getent group docker | cut -f3 -d:)"
    echo "Building ${suffix:+$suffix }Docker image"
    echo "=========================="
    echo "Image: $tag"
    echo "Config: $conf_rel"
    echo "Log: $log"
    echo "=========================="
    echo
    docker build $DOCKER_ARGS -f "$conf" -t "$tag" $build_args "$build_dir/scion.git" | tee "$log"
    docker tag "$tag" "$image_name:latest"
    touch docker/_build/scion.stamp
}

cmd_clean() {
    if [ -z "$1" -o "$1" = "cntrs" ]; then
        stop_cntrs
        del_cntrs
    fi
    [ -z "$1" -o "$1" = "images" ] && del_imgs
    rm -rf docker/_build/
}

common_args() {
    # Limit to 4G of ram, don't allow swapping.
    local args="-h scion -m 4GB --memory-swap=4GB --shm-size=1024M $DOCKER_ARGS"
    args+=" -v /var/run/docker.sock:/var/run/docker.sock"
    args+=" -v $SCION_MOUNT/gen:/home/scion/go/src/github.com/scionproto/scion/gen"
    args+=" -v $SCION_MOUNT/logs:/home/scion/go/src/github.com/scionproto/scion/logs"
    args+=" -v $SCION_MOUNT/gen-certs:/home/scion/go/src/github.com/scionproto/scion/gen-certs"
    args+=" -v $SCION_MOUNT/gen-cache:/home/scion/go/src/github.com/scionproto/scion/gen-cache"
    args+=" -v $SCION_MOUNT/htmlcov:/home/scion/go/src/github.com/scionproto/scion/python/htmlcov"
    args+=" -e SCION_OUTPUT_BASE=$SCION_MOUNT"
    args+=" -e SCION_UID=$(id -u)"
    args+=" -e SCION_GID=$(id -g)"
    args+=" -e DOCKER_GID=$(getent group docker | cut -f3 -d:)"
    args+=" -e SCION_USERSPEC=$(id -un):$(id -gn)"
    args+=" -u root"
    args+=" -e DOCKER0=$(./tools/docker-ip)"
    echo $args
}

cmd_run() {
    set -e
    SCION_MOUNT=${SCION_MOUNT:-$(mktemp -d /tmp/scion_out.XXXXXX)}
    echo "SCION_MOUNT directory: $SCION_MOUNT"
    local img=${SCION_IMG:-scion}
    local args=$(common_args)
    args+=" -i -t --rm --entrypoint=/docker-entrypoint.sh"
    setup_volumes
    docker run $args "$img" "$@"
}

cmd_start() {
    set -e
    SCION_MOUNT=${SCION_MOUNT:-$(mktemp -d /tmp/scion_out.XXXXXX)}
    echo "SCION_MOUNT directory: $SCION_MOUNT"
    local img=${SCION_IMG:-scion}
    local cntr=${SCION_CNTR:-scion}
    if docker container inspect "$cntr" &>/dev/null; then
        echo "Removing stale $cntr container"
        ./tools/quiet docker rm -f "$cntr"
    fi
    local args=$(common_args)
    args+=" --name $cntr"
    setup_volumes
    ./tools/quiet docker container create $args "$img" -c "tail -f /dev/null"
    ./tools/quiet docker start "$cntr"
    # Adjust ownership of mounted dirs
    docker exec "$cntr" /docker-entrypoint.sh
}

cmd_exec() {
    local cntr=${SCION_CNTR:-scion}
    docker exec -it -u scion "$cntr" bash -l -c "$*"
}

cmd_stop() {
    local cntr=${SCION_CNTR:-scion}
    echo "Stopping $cntr container"; ./tools/quiet docker stop "$cntr";
    echo "Removing $cntr container"; ./tools/quiet docker rm "$cntr";
}

setup_volumes() {
    set -e
    for i in gen logs gen-certs gen-cache htmlcov; do
        mkdir -p "$SCION_MOUNT/$i"
        # Check dir exists, and is owned by the current (effective) user. If
        # it's owned by the wrong user, the docker environment won't be able to
        # write to it.
        [ -O "$SCION_MOUNT/$i" ] || { echo "Error: '$SCION_MOUNT/$i' dir not owned by $LOGNAME"; exit 1; }
    done
    # Make sure the socket dirs have the correct permissions. Unlike for the volumes we try to fix
    # the permissions if necessary.
    local disp_dir="/run/shm/dispatcher"
    [ -d "$disp_dir" ] || mkdir "$disp_dir"
    [ $(stat -c "%U" "$disp_dir") == "$LOGNAME" ] || { sudo -p "Fixing ownership of $disp_dir - [sudo] password for %p: " chown $LOGNAME: "$disp_dir"; }
    local sciond_dir="/run/shm/sciond"
    [ -d "$sciond_dir" ] || mkdir "$sciond_dir"
    [ $(stat -c "%U" "$sciond_dir") == "$LOGNAME" ] || { sudo -p "Fixing ownership of $sciond_dir - [sudo] password for %p: " chown $LOGNAME: "$sciond_dir"; }
}

stop_cntrs() {
    local running
    running=$(docker ps -q)
    if [ -n "$running" ]; then
        echo
        echo "Stopping running containers"
        echo "==========================="
        docker stop $running
    fi
}

del_cntrs() {
    local stopped
    stopped=$(docker ps -aq)
    if [ -n "$stopped" ]; then
        echo
        echo "Deleting stopped containers"
        echo "==========================="
        docker rm $stopped
    fi
}

del_imgs() {
    local images
    images=$(docker images | awk '/^<none>/ {print $3}')
    if [ -n "$images" ]; then
        echo
        echo "Deleting unamed images"
        echo "======================"
        docker rmi $images
    fi
}

cmd_help() {
	cat <<-_EOF
	Usage:
	    $PROGRAM base
	    $PROGRAM build
	    $PROGRAM tester
	    $PROGRAM run
	        Run the Docker image.
	    $PROGRAM start
	        Start a Docker container.
	    $PROGRAM exec
	        Execute a command in a running container.
	    $PROGRAM stop
	        Stop the Docker container.
	    $PROGRAM clean
	        Remove all Docker containers and all generated images.
	    $PROGRAM help
	        Show this text.
	_EOF
}


PROGRAM="${0##*/}"
COMMAND="$1"
ARG="$2"

[ $(id -u) -eq 0 ] && { echo "Error: running as root is not allowed!" && exit 1; }

if ! ( groups | grep -q "\<docker\>"; ); then
    echo "Error: you must be in the 'docker' group"
    exit 1
fi

if ! type -p docker &>/dev/null; then
    echo "Error: you don't have docker installed. Please see docker/README.md"
    exit 1
fi

case $COMMAND in
    base)               cmd_base ;;
    build)              cmd_build ;;
    tester)             cmd_tester ;;
    clean)              shift; cmd_clean "$@" ;;
    run)                shift; cmd_run "$@" ;;
    start)              cmd_start ;;
    exec)               shift; cmd_exec "$@" ;;
    stop)               shift; cmd_stop "$@" ;;
    help)               cmd_help ;;
    *)                  cmd_help ;;
esac

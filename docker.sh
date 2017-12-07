#!/bin/bash

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
    docker tag scion_base:latest scionproto/scion_base:pending
}

cmd_build() {
    set -e
    set -o pipefail
    get_params
    copy_tree
    docker_build
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
    echo "Building ${suffix:+$suffix }Docker image"
    echo "=========================="
    echo "Image: $tag"
    echo "Config: $conf_rel"
    echo "Log: $log"
    echo "=========================="
    echo
    docker build $DOCKER_ARGS -f "$conf" -t "$tag" "$build_dir/scion.git" | tee "$log"
    docker tag "$tag" "$image_name:latest"
}

cmd_clean() {
    if [ -z "$1" -o "$1" = "cntrs" ]; then
        stop_cntrs
        del_cntrs
    fi
    [ -z "$1" -o "$1" = "images" ] && del_imgs
    rm -rf docker/_build/
}

cmd_run() {
    # Limit to 4G of ram, don't allow swapping.
    local args="-i -t -h scion -m 4096M --memory-swap=4096M --shm-size=1024M $DOCKER_ARGS"
    args+=" -v $PWD/htmlcov:/home/scion/go/src/github.com/scionproto/scion/htmlcov"
    args+=" -v $PWD/logs:/home/scion/go/src/github.com/scionproto/scion/logs"
    args+=" -v $PWD/sphinx-doc/_build:/home/scion/go/src/github.com/scionproto/scion/sphinx-doc/_build"
    # Can't use --rm in circleci, their environment doesn't allow it, so it
    # just throws an error
    [ -n "$CIRCLECI" ] || args+=" --rm"
    setup_volumes
    docker run $args scion "$@"
}

setup_volumes() {
    set -e
    for i in htmlcov logs sphinx-doc/_build; do
        mkdir -p "$i"
        # Check dir exists, and is owned by the current (effective) user. If
        # it's owned by the wrong user, the docker environment won't be able to
        # write to it.
        [ -O "$i" ] || { echo "Error: '$i' dir not owned by $LOGNAME"; exit 1; }
    done
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
	    $PROGRAM build
	    $PROGRAM run
	        Run the Docker image.
	    $PROGRAM clean
	        Remove all Docker containers and all generated images.
	    $PROGRAM help
	        Show this text.
	_EOF
}


PROGRAM="${0##*/}"
COMMAND="$1"
ARG="$2"

if ! ( [ $(id -u) -eq 0 ] || groups | grep -q "\<docker\>"; ); then
    echo "Error: you must either be root, or in the 'docker' group"
    exit 1
fi

if ! type -p docker &>/dev/null; then
    echo "Error: you don't have docker installed. Please see docker/README.md"
    exit 1
fi

case $COMMAND in
    base)               cmd_base ;;
    build)              cmd_build ;;
    clean)              shift; cmd_clean "$@" ;;
    run)                shift; cmd_run "$@" ;;
    help)               cmd_help ;;
    *)                  cmd_help ;;
esac

#!/bin/bash

branch=
build_dir=
image_tag=

get_params() {
  # If we're on a local branch, use that. If we're on a detached HEAD from a
  # remote branch, or from a bare rev id, use that instead.
  branch=$(git status | head -n1 |
           awk '/^On branch|HEAD detached at/ {print $NF}')
  build_dir="docker/_build/$branch"
  image_tag=$(echo "$branch" | tr '/' '.')
}

cmd_build() {
    set -e
    set -o pipefail
    get_params
    echo
    echo "Copying current working tree for Docker image"
    echo "============================================="
    mkdir -p "${build_dir:?}"
    copy_tree
    echo
    echo "Building Docker image"
    echo "====================="
    docker_build "build.log"
}

copy_tree() {
    # Just in case it's sitting there from a previous failed run
    rm -rf docker/_build/.scion.tmp
    # Ignore timestamps; only update files if their checksums have changed.
    # This prevents Docker from doing unnecessary cache invalidations. As
    # rsync --from-files cannot delete unknown files in the destionation, first
    # rsync to a clean dir using --from-files, then rsync again from that dir
    # to the actual Docker context dir using --delete
    git ls-files -z | rsync -a0 --files-from=- . docker/_build/.scion.tmp/
    rsync -a --delete docker/_build/.scion.tmp/ "${build_dir}/scion.git/"
    # Set all timestamps to the epoch to force docker to only use checksums for
    # checking if a file has changed.
    find "${build_dir}/scion.git/" -print0 | xargs -0 touch --date="@0"
}

docker_build() {
    set -e
    set -o pipefail
    local log_file="$1"; shift
    local image_name="scion"
    echo "Image: $image_name:$image_tag"
    echo "Log: $build_dir/$log_file"
    echo "============================"
    echo
    docker build -t "${image_name:?}:${image_tag:?}" "${build_dir:?}/scion.git" |
        tee "$build_dir/${log_file:?}"
    docker tag -f "$image_name:$image_tag" "$image_name:latest"
}

cmd_clean() {
    stop_cntrs
    del_cntrs
    del_imgs
}

cmd_clean_full() {
    stop_cntrs
    del_cntrs
    del_imgs_full
    rm -rf docker/_build/
}

cmd_run() {
    local args="-i -t --privileged -h scion"
    args+=" -v $PWD/htmlcov:/home/scion/scion.git/htmlcov"
    args+=" -v $PWD/sphinx-doc/_build:/home/scion/scion.git/sphinx-doc/_build"
    # Can't use --rm in circleci, their environment doesn't allow it, so it
    # just throws an error
    [ -n "$CIRCLECI" ] || args+=" --rm"
    setup_volumes
    docker run $args scion "$@"
}

setup_volumes() {
    set -e
    for i in htmlcov sphinx-doc/_build; do
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
    images=$(docker images | grep -E '^(<none>)' | awk '{print $3;}')
    if [ -n "$images" ]; then
        echo
        echo "Deleting unused images"
        echo "======================"
        docker rmi $images
    fi
}

del_imgs_full() {
    local images
    images=$(docker images | grep -E '^(<none>|scion)' | awk '{print $3;}')
    if [ -n "$images" ]; then
        echo
        echo "Deleting all generated images"
        echo "============================="
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
	        Remove all Docker containers and unused images.
	    $PROGRAM clean_full
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
    build)              cmd_build ;;
    clean)              cmd_clean ;;
    clean_full)         cmd_clean_full ;;
    run)                shift; cmd_run "$@" ;;
    help)               cmd_help ;;
    *)                  cmd_help ;;
esac

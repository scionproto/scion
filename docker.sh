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

cmd_build_basic() {
    set -e
    set -o pipefail
    get_params
    echo
    echo "Copying current working tree for Docker image"
    echo "============================================="
    mkdir -p "${build_dir:?}"
    # Just in case it's sitting there from a previous failed run
    rm -rf docker/_build/.scion.tmp
    # Ignore timestamps; only update files if their checksums have changed.
    # This prevents Docker from doing unnecessary cache invalidations. As
    # rsync --from-files cannot delete unknown files in the destionation, first
    # rsync to a clean dir using --from-files, then rsync again from that dir
    # to the actual Docker context dir using --delete
    git ls-files -z | rsync -a0 --files-from=- . docker/_build/.scion.tmp/
    rsync -rlpc --delete --info=FLIST2,STATS \
      docker/_build/.scion.tmp/ "${build_dir}/scion.git/"
    # Cleanup the temp directory
    rm -rf docker/_build/.scion.tmp
    echo
    echo "Building Docker basic image"
    echo "==========================="
    cp -a docker/Dockerfile "$build_dir"
    docker_build "scion/basic" "build-basic.log"
}

cmd_build_full() {
    set -e
    set -o pipefail
    cmd_build_basic
    echo
    echo "Building Docker full image"
    echo "============================"
    cp -a docker/Dockerfile.full "$build_dir/Dockerfile"
    docker_build "scion/full" "build-full.log"
}

docker_build() {
    set -e
    set -o pipefail
    local image_name="$1"; shift
    local log_file="$1"; shift
    echo "Image: $image_name:$image_tag"
    echo "Log: $build_dir/$log_file"
    echo "============================"
    echo
    docker build -t "${image_name:?}:${image_tag:?}" "${build_dir:?}" |
      tee "$build_dir/${log_file:?}"
    docker tag "$image_name:$image_tag" "$image_name:latest"
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

cmd_run_basic() {
    docker run -i -t --rm --privileged -h scionbasic scionbasic "$@"
}

cmd_run_full() {
    docker run -i -t --rm --privileged -h scionfull scionfull "$@"
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
	    $PROGRAM build_full
            Build both Docker images (with all scion setup done)
	    $PROGRAM build_basic
            Build the basic Docker image (with just scion deps installed)
	    $PROGRAM run
	    $PROGRAM run_full
	        Run the full Docker image.
	    $PROGRAM run_basic
	        Run the basic Docker image.
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
    build|build_full)   cmd_build_full ;;
    build_basic)        cmd_build_basic ;;
    clean)              cmd_clean ;;
    clean_full)         cmd_clean_full ;;
    run|run_full)       shift; cmd_run_full "$@" ;;
    run_basic)          shift; cmd_run_basic "$@" ;;
    help)               cmd_help ;;
    *)                  cmd_help ;;
esac
exit 0

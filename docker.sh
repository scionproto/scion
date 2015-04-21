#!/bin/bash

cmd_build_basic() {
    stop_cntrs
    del_cntrs
    echo
    echo "Copying current working tree for Docker image"
    echo "============================================="
    mkdir -p docker/_build/
    # Ignore timestamps; only update files if their checksums have changed
    # Prevents Docker from doing unnecessary cache invalidations.
    git ls-files -z | rsync -rlpc0 --delete --info=FLIST2,STATS --files-from=- . docker/_build/scion.git/
    echo
    echo "Setting up Docker basic image"
    echo "============================="
    docker build -t scionbasic docker || exit 1
    del_imgs
}

cmd_build_full() {
    cmd_build_basic
    echo
    echo "Setting up Docker full image"
    echo "============================"
    docker build -t scionfull - < docker/Dockerfile.full || exit 1
    del_imgs
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
    docker run -i -t --rm --privileged -h scionbasic scionbasic
}

cmd_run_full() {
    docker run -i -t --rm --privileged -h scionfull scionfull
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

case $COMMAND in
    build|build_full)   cmd_build_full ;;
    build_basic)        cmd_build_basic ;;
    clean)              cmd_clean ;;
    clean_full)         cmd_clean_full ;;
    run|run_full)       cmd_run_full ;;
    run_basic)          cmd_run_basic ;;
    help)               cmd_help ;;
    *)                  cmd_help ;;
esac
exit 0

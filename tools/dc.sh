#!/bin/bash

cmd_help() {
	echo
	cat <<-_EOF
	Usage:
	    $PROGRAM scion [docker-compose command]
	        Run docker-compose command for scion services.
	    $PROGRAM utils [docker-compose command]
	        Run docker-compose command for util services.
	_EOF
}

PROGRAM="${0##*/}"
DC_ENV="$1"
shift

case "$DC_ENV" in
    "scion") COMPOSE_FILE="gen/base-dc.yml:gen/scion-dc.yml" docker-compose "$@" ;;
    "utils") COMPOSE_FILE="gen/base-dc.yml:gen/utils-dc.yml" docker-compose "$@" ;;
    "tester") docker exec -t -e PYTHONPATH=python/: tester "$@" ;;
    *)  cmd_help; exit 1 ;;
esac

#!/bin/bash

cmd_help() {
    echo
	cat <<-_EOF
	Usage:
	    $PROGRAM scion [docker-compose command]
	        Run docker-compose command for scion services.
	_EOF
}

PROGRAM="${0##*/}"
DC_ENV="$1"
shift

case "$DC_ENV" in
    "scion") COMPOSE_FILE="gen/scion-dc.yml" docker-compose --no-ansi "$@" ;;
    *)  cmd_help; exit 1 ;;
esac

#!/bin/bash

set -e

COLOR=$(tput setaf 12)
RESET=$(tput sgr0)

log() {
    echo "$COLOR=======> $@ $RESET"
}

log "Switching to master branch"
git checkout master
log "Fetching upstream"
git fetch --prune --multiple upstream origin
log "Updating master"
git merge --ff-only upstream/master master
git push
log "Merged branches:"
git branch --merged
log "Done"

#!/bin/bash

NC='\033[0m'


print_green() {
    GREEN='\033[0;32m'
    printf "${GREEN}$1${NC} $2 \n"
}

print_red() {
    RED='\033[0;31m'
    printf "${RED}$1${NC} $2 \n"
}

print_yellow() {
    YELLOW='\033[0;34m'
    printf "${YELLOW}$1${NC} $2 \n"
}

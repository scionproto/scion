if [ -t 1 ]; then
    GREEN=$(tput setaf 2)
    RED=$(tput setaf 9)
    YELLOW=$(tput setaf 11)
    NC=$(tput sgr0)
fi

print_green() {
    local prefix="$1"
    shift
    printf "${GREEN}$prefix${NC} $@\n"
}

print_red() {
    local prefix="$1"
    shift
    printf "${RED}$prefix${NC} $@\n"
}

print_yellow() {
    local prefix="$1"
    shift
    printf "${YELLOW}$prefix${NC} $@\n"
}

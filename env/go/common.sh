go_installed() {
    type -p go &>/dev/null
}

go_ver_check() {
    go version | sed -r 's/.* go([[:digit:]]+)\.([[:digit:]]+)\.([[:digit:]]+) .*/\1 \2 \3/' | \
        {
            read maj min patch
            # Must be go 1.x
            [[ $maj -eq 1 ]] || exit 1
            # go 1.10+ are (presumably) fine
            [[ $min -gt 9 ]] && exit 0
            # if go 1.9.x, must be >= .4
            [[ $min -eq 9 && $patch -ge 4 ]] && exit 0
            # anything else
            exit 1
        }
}

go_ver_msg() {
    echo "Go version >= 1.9.4 required. Unsupported go version found ($(type -p go)): $(go version)"
}

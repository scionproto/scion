go_installed() {
    type -p go &>/dev/null
}

go_ver_check() {
    go version | grep -q ' go1\.9\>'
}

go_ver_msg() {
    echo "Go version 1.9.x required. Unsupported go version found ($(type -p go)): $(go version)"
}

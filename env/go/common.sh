go_installed() {
    type -p go &>/dev/null
}

go_ver_check() {
    go version | grep -q ' go1\.8\>'
}

go_ver_msg() {
    echo "Go version 1.8.x required. Unsupported go version found ($(type -p go)): $(go version)"
}

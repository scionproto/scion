go_installed() {
    type -p go &>/dev/null
}

go_ver_check() {
    go version | cut -f3 -d' ' | awk -F. '{if ($1 == "go1" && $2 == "9" && $3 >= 4) { exit 0 } else { exit 1 }}'
}

go_ver_msg() {
    echo "Go version 1.9.x (where x >= 4) required. Unsupported go version found ($(type -p go)): $(go version)"
}

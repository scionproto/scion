if [ $(id -u) = "0" ]; then
    echo "ERROR: Running $0 as root is not supported (and is a bad idea, anyway)"
    exit 1
fi

lower() {
    tr '[:upper:]' '[:lower:']
}

pip_installed() {
    "${1:?}" --disable-pip-version-check freeze --all | lower | LC_ALL=C sort
}

pip_reqs() {
    # Extract package==version from pip requirement files, ignoring blank and comment lines.
    awk '
      /^#/ {next}
      /^[[:blank:]]*$/ {next}
      {print $1}
    ' "${1:?}" | lower | LC_ALL=C sort
}

pip_compare() {
    local pip="${1:?}"
    local req="${2:?}"
    LC_ALL=C comm --check-order -13 <(pip_installed "$pip") <(pip_reqs "$req")
}

pip_install() {
    local pip="${1:?}"
    local req="${2:?}"
    "$pip" --disable-pip-version-check install --user --require-hashes -r "$req"
}

sudo_preload() {
    LD_PRELOAD= sudo LD_PRELOAD="$LD_PRELOAD" "$@"
}

if [ -t 1 ]; then
    CURL_PARAM="-#"
else
    CURL_PARAM="-s"
fi

#!/bin/bash

set -e

cmd_all() {
    cmd_pkgs
    cmd_pip
    cmd_pipweb
    cmd_zlog
    cmd_golang
    cmd_misc
}

cmd_pkgs() {
    if [ -e /etc/debian_version ]; then
        pkgs_debian
    else
        echo "As this is not a debian-based OS, please install the equivalents of these packages:"
        cat pkgs_debian.txt
    fi
}

pkgs_debian() {
    local pkgs=""
    echo "Checking for necessary debian packages"
    for pkg in $(< pkgs_debian.txt); do
        pkg_deb_chk $pkg || pkgs+="$pkg "
    done
    if [ -n "$pkgs" ]; then
        echo "Installing missing necessary packages: $pkgs"
        sudo DEBIAN_FRONTEND=noninteractive apt-get install $APTARGS --no-install-recommends $pkgs
    fi
}

pkg_deb_chk() {
    dpkg -s ${1:?} 2>/dev/null | grep -q "^Status: install ok installed";
}

cmd_pip() {
    echo "Installing necessary packages from pip3"
    pip3 install --user --require-hashes -r requirements.txt
}

cmd_pipweb() {
    echo "Installing necessary packages from pip3 for scion-web"
    # FIXME(kormat): add hashes
    pip3 install --user -r sub/web/requirements.txt
}

cmd_zlog() {
    pkg_deb_chk zlog && return
    [ -f /usr/lib/libzlog.so ] && return
    local tmpdir=$(mktemp -d /tmp/zlog.XXXXXXX)
    curl -L https://github.com/HardySimpson/zlog/archive/1.2.12.tar.gz | tar xzf - --strip-components=1 -C $tmpdir
    (
        cd $tmpdir
        make -j6
        echo "ldconfig" >> postinstall-pak
        echo "ldconfig" >> postremove-pak
        sudo checkinstall -D --pkgname zlog --nodoc -y --deldoc --deldesc --strip=no --stripso=no --pkgversion 1.2.12
        sudo rm *deb
    )
    rm -r "${tmpdir:?}"
}

cmd_golang() {
    echo "Checking for go 1.6"
    if ! chk_go; then
        echo "Installing golang-1.6 from apt"
        # Include git, as it's needed for fetching go deps. Relevant for
        # testing building Go code inside docker.
        sudo DEBIAN_FRONTEND=noninteractive apt-get install $APTARGS --no-install-recommends golang-1.6 git
    fi
    if ! type -P govendor &>/dev/null; then
        (
            HOST=github.com
            USER=kardianos
            PROJECT=govendor
            COMMIT=120a6099270fc9360236f4383430e2adda6181cc
            GOPATH_BASE=${GOPATH%%:*}
            echo "Installing govendor dep manager"
            mkdir -p "${GOPATH_BASE}/src/$HOST/$USER"
            cd "${GOPATH_BASE}/src/$HOST/$USER/"
            [ ! -d "$PROJECT" ] && git clone "git@$HOST:$USER/$PROJECT.git"
            cd "$PROJECT"
            git fetch
            git checkout "$COMMIT"
            go install -v
        );
    fi
    echo "Downloading go dependencies (via govendor)"
    # `make -C go` breaks if there are symlinks in $PWD
    ( cd go && make deps )
    echo "Copying go-capnproto2's go.capnp into proto/"
    cp go/vendor/zombiezen.com/go/capnproto2/std/go.capnp proto/go.capnp
}

chk_go() {
    type -P go &>/dev/null && go version | grep -Eq ' (go1.6|go1.7)'
}

cmd_misc() {
    echo "Installing supervisor packages from pip2"
    pip2 install --user --require-hashes \
        'https://pypi.python.org/packages/b6/ae/e6d731e4b9661642c1b20591d8054855bb5b8281cbfa18f561c2edd783f7/meld3-1.0.2-py2.py3-none-any.whl#sha256=b28a9bfac342aadb4557aa144bea9f8e6208bfb0596190570d10a892d35ff7dc' \
        'https://pypi.python.org/packages/80/37/964c0d53cbd328796b1aeb7abea4c0f7b0e8c7197ea9b0b9967b7d004def/supervisor-3.3.1.tar.gz#sha256=fc3af22e5a7af2f6c3be787acf055c1c17777f5607cd4dc935fe633ab97061fd'
    # - supervisor-quick can't be installed at the same time as supervisor, as
    #   its setup.py imports supervisor_quick.py, which then tries (and fails) to
    #   import supervisor.supervisorctl, which hasn't been installed yet.
    # - Use --no-deps to avoid having to specify the versions+hashes of supervisor/meld3 again
    pip2 install --user --require-hashes --no-deps \
        'https://pypi.python.org/packages/a9/39/aafe116403d625c1034aa442b22c80287b4c4ab6c818b794dd9282a00d03/supervisor-quick-0.1.4.tar.gz#sha256=8be428cc10e868b2d2dfc57fc5b9ea1b2652d7c78b60313750a50ff77f92a9f3'
}

cmd_help() {
	cat <<-_EOF
	$PROGRAM CMD
	
	Usage:
	    $PROGRAM all
	        Install all dependencies (recommended).
	    $PROGRAM pkgs
	        Install all system package dependencies (e.g. via apt-get).
	        Uses sudo.
	    $PROGRAM pip
	        Install all pip package dependencies (using --user, so no root
	        access required)
	    $PROGRAM pipweb
	        Install all pip package dependencies of scion-web (using --user, so
	        no root access required)
	    $PROGRAM zlog
	        Install libzlog
	    $PROGRAM golang
	        Install golang-1.6
	    $PROGRAM misc
	        Install any additional packages not from the first 2 sources.
	    $PROGRAM help
	        Show this text.
	_EOF
}
# END subcommand functions

PROGRAM="${0##*/}"
COMMAND="$1"
shift || { cmd_help; exit; }

case "$COMMAND" in
    all|pkgs|pip|pipweb|golang|zlog|misc)
            "cmd_$COMMAND" "$@" ;;
    help)  cmd_help ;;
    *)  cmd_help; exit 1 ;;
esac

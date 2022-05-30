#!/bin/bash

set -o pipefail

in_red() {
    tput setaf 1
    echo "$1"
    tput sgr0
}

run_silently() {
    tmpfile=$(mktemp /tmp/scion-silent.XXXXXX)
    $@ >>$tmpfile 2>&1
    if [ $? -ne 0 ]; then
        cat $tmpfile
        return 1
    fi
    return 0
}

go_lint() {
    lint_header "go"
    local TMPDIR=$(mktemp -d /tmp/scion-lint.XXXXXXX)
    # Find go files to lint, excluding generated code. For linelen and misspell.
    find -type f -iname '*.go' \
      -a '!' -ipath '*.pb.go' \
      -a '!' -ipath '*.gen.go' \
      -a '!' -ipath './antlr/*' \
      -a '!' -ipath '*/node_modules/*' \
      -a '!' -ipath './scion-pki/certs/certinfo.go' \
      -a '!' -ipath './scion-pki/certs/certformat.go' \
      -a '!' -ipath './tools/lint/*/testdata/src/*' \
      -a '!' -ipath '*mock_*' > $TMPDIR/gofiles.list
    lint_step "Building lint tools"

    run_silently bazel build //:lint || return 1
    tar -xf bazel-bin/lint.tar -C $TMPDIR || return 1
    local ret=0
    lint_step "gofmt"
    # TODO(sustrik): At the moment there are no bazel rules for gofmt.
    # See: https://github.com/bazelbuild/rules_go/issues/511
    # Instead we'll just run the commands from Go SDK directly.
    GOSDK=$(bazel info output_base 2>/dev/null)/external/go_sdk/bin
    out=$(xargs -a $TMPDIR/gofiles.list $GOSDK/gofmt -d -s);
    if [ -n "$out" ]; then in_red "$out"; ret=1; fi
    lint_step "linelen (lll)"
    out=$($TMPDIR/lll -w 4 -l 100 --files -e '`comment:"|`ini:"|https?:|`sql:"|gorm:"|`json:"|`yaml:|nolint:lll' < $TMPDIR/gofiles.list)
    if [ -n "$out" ]; then in_red "$out"; ret=1; fi
    lint_step "misspell"
    out=$(xargs -a $TMPDIR/gofiles.list $TMPDIR/misspell -error)
    if [ -n "$out" ]; then in_red "$out"; ret=1; fi
    lint_step "licensechecker"
    out=$(xargs -a $TMPDIR/gofiles.list tools/licensechecker.py)
    if [ -n "$out" ]; then in_red "$out"; ret=1; fi
    lint_step "bazel"
    run_silently make gazelle GAZELLE_MODE=diff || ret=1
    bazel test --config lint || ret=1
    # Clean up the binaries
    rm -rf $TMPDIR
    return $ret
}

protobuf_lint() {
    lint_header "protobuf"
    local TMPDIR=$(mktemp -d /tmp/scion-lint.XXXXXXX)
    run_silently bazel build //:lint || return 1
    tar -xf bazel-bin/lint.tar -C $TMPDIR || return 1
    local ret=0
    lint_step "check files"
    $TMPDIR/buf check lint || return 1
}

bazel_lint() {
    lint_header "bazel"
    local ret=0
    run_silently bazel run //:buildifier_check || ret=1
    if [ $ret -ne 0 ]; then
        printf "\nto fix run:\nbazel run //:buildifier\n"
    fi
    return $ret
}

md_lint() {
    lint_header "markdown"
    lint_step "mdlint"
    ./tools/mdlint
}

semgrep_lint() {
    lint_header "semgrep"
    lint_step "custom rules"
    docker run --rm -v "${PWD}:/src" returntocorp/semgrep@sha256:3bef9d533a44e6448c43ac38159d61fad89b4b57f63e565a8a55ca265273f5ba \
       semgrep --config=/src/tools/lint/semgrep --error
}

openapi_lint() {
    lint_header "openapi"
    lint_step "spectral"
    make -C spec lint
}

lint_header() {
    printf "\nlint $1\n==============\n"
}

lint_step() {
    echo "======> $1"
}

ret=0
go_lint || ret=1
bazel_lint || ret=1
protobuf_lint || ret=1
md_lint || ret=1
semgrep_lint || ret=1
openapi_lint || ret=1
exit $ret

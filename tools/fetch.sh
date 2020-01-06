#!/bin/bash

# This script will create a fake BUILD.bazel file that
# can be used to fetch all external dependencies.
# After the file is generated and stored along the WORKSPACE
# do "bazel fetch //:fetch" to actually dowload the repos.

set -e

ROOTDIR=$(dirname "$0")/..

extra_import() {
    # For dependencies listed below the go code is in a sub folder.
    # All go_repositories which don't have go code in the root folder must be
    # listed here. Otherwise the fetching doesn't work.
    case "$1" in
        com_github_antlr_antlr4)
            echo "runtime/Go/antlr" ;;
        com_github_beorn7_perks)
            echo "histogram" ;;
        com_github_golang_mock)
            echo "gomock" ;;
        com_github_google_go_cmp)
            echo "cmp" ;;
        com_github_matttproud_golang_protobuf_extensions)
            echo "ext" ;;
        com_github_oncilla_gochecks)
            echo "serrorscheck" ;;
        com_github_pierrec_xxhash)
            echo "xxhsum" ;;
        com_github_prometheus_client_golang)
            echo "prometheus" ;;
        com_github_prometheus_common)
            echo "model" ;;
        com_github_syndtr_gocapability)
            echo "capability" ;;
        org_golang_x_crypto)
            echo "acme" ;;
        com_github_buildkite_go_buildkite)
            echo "buildkite" ;;
        com_github_google_go_querystring)
            echo "query" ;;
        com_github_uber_jaeger_lib)
            echo "metrics" ;;
        com_github_sergi_go_diff)
            echo "diffmatchpatch" ;;
        org_golang_x_net)
            echo "ipv4" ;;
        org_golang_x_sys)
            echo "unix" ;;
        org_golang_x_sync)
            echo "semaphore" ;;
        org_golang_x_tools)
            echo "go/packages" ;;
        com_github_pmezard_go_difflib)
            echo "difflib" ;;
        com_github_bazelbuild_buildtools)
            echo "build" ;;
        *)
            echo "" ;;
    esac
}

# Add any bazel packages to prefetch to the beginning of the following block.
cat <<EOF
load("@com_github_jmhodges_bazel_gomock//:gomock.bzl", "gomock")
load("@io_bazel_rules_go//go:def.bzl", "nogo")

nogo(
    name = "nogo",
    visibility = ["//visibility:public"],
)

genrule(
    name = "fetch",
    outs = ["dummy"],
    cmd = "touch dummy",
    tools = [
        "@debian_stretch//file:Packages.json",
        "@package_bundle//file:packages.bzl",
EOF

for q in $(bazel query "kind('go_repository rule', //external:*)" --noshow_progress); do
    # Ignore some indirect test dependencies (will not be used) that would require extra_import for fetching
    if echo $q | grep -qF -e "com_github_jmhodges_bazel_gomock" \
                          -e "com_github_tinylib_msgp" \
                          -e "com_github_kylelemons_godebug" \
                          -e "com_github_gopherjs_gopherjs" \
                          -e "com_github_golang_protobuf" \
                          -e "com_github_gogo_protobuf" \
                          -e "com_github_go_kit_kit" \
                          -e "com_github_davecgh_go_spew" \
                          -e "com_github_cloudflare_sidh" \
                          -e "org_golang_google_appengine" \
                          -e "com_github_google_go_containerregistry" \
                          -e "com_github_onsi_ginkgo" \
                          -e "com_github_onsi_gomega" \
                          -e "org_golang_google_genproto"
    then
        continue
    fi
    if [[ $q == //external* ]]; then
        dep_name=${q#//external:} # remove "//external:" in front.
        extra=$(extra_import $dep_name)
        echo "        \"@$dep_name//$extra:go_default_library\","
    fi
done

cat <<EOF
    ]
)
EOF

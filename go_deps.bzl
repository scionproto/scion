load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_deps():
    # Note the comments in the rules below. These point to an arbitrary directory within the repo
    # that contains Go files. The comment is not needed if the root directory contains Go files.
    # To understand how it works see tools/fetch.sh
    go_repository(
        name = "com_github_burntsushi_toml",
        commit = "a368813c5e648fee92e5f6c30e3944ff9d5e8895",
        importpath = "github.com/BurntSushi/toml",
    )

    go_repository(
        name = "com_github_antlr_antlr4",
        commit = "be58ebffde8e29c154192c019608f0a5b8e6a064",
        importpath = "github.com/antlr/antlr4",  # runtime/Go/antlr
    )

    go_repository(
        name = "com_github_axw_gocov",
        commit = "54b98cfcac0c63fb3f9bd8e7ad241b724d4e985b",
        importpath = "github.com/axw/gocov",
    )

    go_repository(
        name = "com_github_beorn7_perks",
        commit = "4c0e84591b9aa9e6dcfdf3e020114cd81f89d5f9",
        importpath = "github.com/beorn7/perks",  # histogram
    )

    go_repository(
        name = "com_github_dchest_cmac",
        commit = "62ff55a1048c485e83f1882466f535da624e944a",
        importpath = "github.com/dchest/cmac",
    )

    go_repository(
        name = "com_github_go_ini_ini",
        commit = "32e4c1e6bc4e7d0d8451aa6b75200d19e37a536a",
        importpath = "github.com/go-ini/ini",
    )

    go_repository(
        name = "com_github_go_stack_stack",
        commit = "100eb0c0a9c5b306ca2fb4f165df21d80ada4b82",
        importpath = "github.com/go-stack/stack",
    )

    go_repository(
        name = "com_github_golang_mock",
        commit = "73dc87cad333b55a02058f4b3d872dbbafddc2b0",
        importpath = "github.com/golang/mock",  # gomock
    )

    go_repository(
        name = "com_github_google_go_cmp",
        commit = "2248b49eaa8e1c8c0963ee77b40841adbc19d4ca",
        importpath = "github.com/google/go-cmp",  # cmp
    )

    go_repository(
        name = "com_github_google_gopacket",
        commit = "102d5ca2098cc070c7fdc9d7dbd504658bc92363",
        importpath = "github.com/google/gopacket",
    )

    go_repository(
        name = "com_github_hashicorp_golang_lru",
        commit = "0fb14efe8c47ae851c0034ed7a448854d3d34cf3",
        importpath = "github.com/hashicorp/golang-lru",
    )

    go_repository(
        name = "com_github_inconshreveable_log15",
        commit = "944cbfb97b448e4f63f0bdb69c2850e3de1aeae9",
        importpath = "github.com/inconshreveable/log15",
    )

    go_repository(
        name = "com_github_inconshreveable_mousetrap",
        commit = "76626ae9c91c4f2a10f34cad8ce83ea42c93bb75",
        importpath = "github.com/inconshreveable/mousetrap",
    )

    go_repository(
        name = "com_github_jtolds_gls",
        commit = "b4936e06046bbecbb94cae9c18127ebe510a2cb9",
        importpath = "github.com/jtolds/gls",
    )

    go_repository(
        name = "com_github_kormat_fmt15",
        commit = "ee69fecb2656a4de8ac47df338ad7e7f9e056dd5",
        importpath = "github.com/kormat/fmt15",
    )

    go_repository(
        name = "com_github_lucas_clemente_quic_go",
        commit = "fd7246d7ed6eeb79eb4dc8b7b1bfa8a13047105a",
        importpath = "github.com/lucas-clemente/quic-go",
    )

    go_repository(
        name = "com_github_mattn_go_colorable",
        commit = "6c903ff4aa50920ca86087a280590b36b3152b9c",
        importpath = "github.com/mattn/go-colorable",
    )

    go_repository(
        name = "com_github_mattn_go_isatty",
        commit = "fc9e8d8ef48496124e79ae0df75490096eccf6fe",
        importpath = "github.com/mattn/go-isatty",
    )

    go_repository(
        name = "com_github_mattn_go_sqlite3",
        commit = "b3511bfdd742af558b54eb6160aca9446d762a19",
        importpath = "github.com/mattn/go-sqlite3",
    )

    go_repository(
        name = "com_github_matttproud_golang_protobuf_extensions",
        commit = "c12348ce28de40eed0136aa2b644d0ee0650e56c",
        importpath = "github.com/matttproud/golang_protobuf_extensions",  # ext
    )

    go_repository(
        name = "com_github_patrickmn_go_cache",
        commit = "5633e0862627c011927fa39556acae8b1f1df58a",
        importpath = "github.com/patrickmn/go-cache",
    )

    go_repository(
        name = "com_github_pierrec_lz4",
        commit = "08c27939df1bd95e881e2c2367a749964ad1fceb",
        importpath = "github.com/pierrec/lz4",
    )

    go_repository(
        name = "com_github_pierrec_xxhash",
        commit = "a0006b13c722f7f12368c00a3d3c2ae8a999a0c6",
        importpath = "github.com/pierrec/xxHash",  # xxhsum
    )

    go_repository(
        name = "com_github_prometheus_client_golang",
        commit = "170205fb58decfd011f1550d4cfb737230d7ae4f",  #v1.1.0
        importpath = "github.com/prometheus/client_golang",  # prometheus
    )

    go_repository(
        name = "com_github_prometheus_client_model",
        commit = "14fe0d1b01d4d5fc031dd4bec1823bd3ebbe8016",
        importpath = "github.com/prometheus/client_model",
    )

    go_repository(
        name = "com_github_prometheus_common",
        commit = "31bed53e4047fd6c510e43a941f90cb31be0972a",  #v0.6.0
        importpath = "github.com/prometheus/common",  # model
    )

    go_repository(
        name = "com_github_prometheus_procfs",
        commit = "3f98efb27840a48a7a2898ec80be07674d19f9c8",  #v0.0.3
        importpath = "github.com/prometheus/procfs",
    )

    go_repository(
        name = "com_github_smartystreets_assertions",
        commit = "b2de0cb4f26d0705483a2f495d89896d0b808573",
        importpath = "github.com/smartystreets/assertions",
    )

    go_repository(
        name = "com_github_smartystreets_goconvey",
        commit = "63cc4eee0dbc998a86d3aef8b7d7eb8fc765b748",
        importpath = "github.com/smartystreets/goconvey",
        vcs = "git",
        remote = "https://github.com/kormat/goconvey.git",
    )

    go_repository(
        name = "com_github_songgao_water",
        commit = "fd331bda3f4bbc9aad07ccd4bd2abaa1e363a852",
        importpath = "github.com/songgao/water",
    )

    go_repository(
        name = "com_github_spf13_cobra",
        commit = "cd30c2a7e91a1d63fd9a0027accf18a681e9d50b",
        importpath = "github.com/spf13/cobra",
    )

    go_repository(
        name = "com_github_spf13_pflag",
        commit = "1ce0cc6db4029d97571db82f85092fccedb572ce",
        importpath = "github.com/spf13/pflag",
    )

    go_repository(
        name = "com_github_syndtr_gocapability",
        commit = "e7cb7fa329f456b3855136a2642b197bad7366ba",
        importpath = "github.com/syndtr/gocapability",  # capability
    )

    go_repository(
        name = "com_github_vishvananda_netlink",
        commit = "177f1ceba557262b3f1c3aba4df93a29199fb4eb",
        importpath = "github.com/vishvananda/netlink",
    )

    go_repository(
        name = "com_github_vishvananda_netns",
        commit = "54f0e4339ce73702a0607f49922aaa1e749b418d",
        importpath = "github.com/vishvananda/netns",
    )

    go_repository(
        name = "org_golang_x_crypto",
        commit = "8ac0e0d97ce45cd83d1d7243c060cb8461dda5e9",
        importpath = "golang.org/x/crypto",  # acme
    )

    go_repository(
        name = "in_gopkg_natefinch_lumberjack_v2",
        commit = "e21e5cbec0cd0861b9dc302736ad5666c529d93f",
        importpath = "gopkg.in/natefinch/lumberjack.v2",
    )

    go_repository(
        name = "in_gopkg_restruct_v1",
        commit = "80ede2e57cc280052ab88753387703aa62475571",
        importpath = "gopkg.in/restruct.v1",
    )

    go_repository(
        name = "in_gopkg_yaml_v2",
        commit = "51d6538a90f86fe93ac480b35f37b2be17fef232",
        importpath = "gopkg.in/yaml.v2",
    )

    go_repository(
        name = "com_zombiezen_go_capnproto2",
        commit = "ddfb9bb855fad9979ae59da7211fca20967d5669",
        importpath = "zombiezen.com/go/capnproto2",
    )

    go_repository(
        name = "com_github_sergi_go_diff",
        commit = "da645544ed44df016359bd4c0e3dc60ee3a0da43",
        importpath = "github.com/sergi/go-diff",  # diffmatchpatch
    )

    go_repository(
        name = "com_github_stretchr_testify",
        commit = "34c6fa2dc70986bccbbffcc6130f6920a924b075",
        importpath = "github.com/stretchr/testify",
    )

    go_repository(
        name = "com_github_buildkite_go_buildkite",
        commit = "568b6651b687ccf6893ada08086ce58b072538b6",
        importpath = "github.com/buildkite/go-buildkite",  # buildkite
    )

    go_repository(
        name = "com_github_google_go_querystring",
        commit = "c8c88dbee036db4e4808d1f2ec8c2e15e11c3f80",
        importpath = "github.com/google/go-querystring",  # query
    )

    go_repository(
        name = "com_github_opentracing_opentracing_go",
        commit = "659c90643e714681897ec2521c60567dd21da733",
        importpath = "github.com/opentracing/opentracing-go",
    )

    go_repository(
        name = "com_github_uber_jaeger_client_go",
        commit = "2f47546e3facd43297739439600bcf43f44cce5d",
        importpath = "github.com/uber/jaeger-client-go",
    )

    go_repository(
        name = "com_github_uber_jaeger_lib",
        commit = "0e30338a695636fe5bcf7301e8030ce8dd2a8530",
        importpath = "github.com/uber/jaeger-lib",  # metrics
    )

    go_repository(
        name = "com_github_pkg_errors",
        commit = "27936f6d90f9c8e1145f11ed52ffffbfdb9e0af7",
        importpath = "github.com/pkg/errors",
    )

    go_repository(
        name = "org_golang_x_xerrors",
        commit = "a985d3407aa71f30cf86696ee0a2f409709f22e1",
        importpath = "golang.org/x/xerrors",
    )

    go_repository(
        name = "com_github_iancoleman_strcase",
        commit = "e506e3ef73653e84c592ba44aab577a46678f68c",
        importpath = "github.com/iancoleman/strcase",
    )

    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net", # ipv4
        sum = "h1:QPlSTtPE2k6PZPasQUbzuK3p9JbS+vMXYVto8g/yrsg=",
        version = "v0.0.0-20191105084925-a882066a44e0",
    )

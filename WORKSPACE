
# Generic stuff for dealing with repositories.
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# Bazel rules for Golang
git_repository(
    name = "io_bazel_rules_go",
    remote = "https://github.com/bazelbuild/rules_go.git",
    tag = "0.17.0",
)
load("@io_bazel_rules_go//go:deps.bzl", "go_download_sdk", "go_rules_dependencies", "go_register_toolchains")
go_rules_dependencies()
go_download_sdk(
    name = "go_sdk",
    sdks = {
        "linux_amd64":  ("go1.11.5.linux-amd64.tar.gz", "ff54aafedff961eb94792487e827515da683d61a5f9482f668008832631e5d25"),
    },
)
go_register_toolchains(nogo="@//:nogo")

# Gazelle
http_archive(
    name = "bazel_gazelle",
    urls = ["https://github.com/bazelbuild/bazel-gazelle/releases/download/0.16.0/bazel-gazelle-0.16.0.tar.gz"],
    sha256 = "7949fc6cc17b5b191103e97481cf8889217263acf52e00b560683413af204fcb",
)
load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")
gazelle_dependencies()

# Note the comments in the rules below. These point to an arbitrary directory within the repo
# that contains Go files. The comment is not needed if the root directory contains Go files.
# To understand how it works see tools/fetch.sh
# Dependencies
go_repository(
    name = "com_github_burntsushi_toml",
    importpath = "github.com/BurntSushi/toml",
    commit = "a368813c5e648fee92e5f6c30e3944ff9d5e8895",
)
go_repository(
    name = "com_github_jeanmertz_lll",
    importpath = "github.com/JeanMertz/lll",
    commit = "c7683829ec0c1f892b2d0468356597573afafb03",
)
go_repository(
    name = "com_github_aead_chacha20",
    importpath = "github.com/aead/chacha20",
    commit = "e2538746bfea853aaa589feb8ec46bd46ee78f86",
)
go_repository(
    name = "com_github_alexflint_go_arg",
    importpath = "github.com/alexflint/go-arg",
    commit = "f7c0423bd11ee80ab81d25c6d46f492998af8547",
)
go_repository(
    name = "com_github_alexflint_go_scalar",
    importpath = "github.com/alexflint/go-scalar",
    commit = "e80c3b7ed292b052c7083b6fd7154a8422c33f65",
)
go_repository(
    name = "com_github_antlr_antlr4",
    importpath = "github.com/antlr/antlr4", # runtime/Go/antlr
    commit = "d4d7e3d3bc3b65bb00579fe826834a9263fa45e6",
)
go_repository(
    name = "com_github_axw_gocov",
    importpath = "github.com/axw/gocov",
    commit = "54b98cfcac0c63fb3f9bd8e7ad241b724d4e985b",
)
go_repository(
    name = "com_github_beorn7_perks",
    importpath = "github.com/beorn7/perks", # histogram
    commit = "4c0e84591b9aa9e6dcfdf3e020114cd81f89d5f9",
)
go_repository(
    name = "com_github_bifurcation_mint",
    importpath = "github.com/bifurcation/mint",
    commit = "198357931e6129b810c9c77c12e0dd754846170c",
)
go_repository(
    name = "com_github_client9_misspell",
    importpath = "github.com/client9/misspell",
    commit = "c0b55c8239520f6b5aa15a0207ca8b28027ba49e",
)
go_repository(
    name = "com_github_dchest_cmac",
    importpath = "github.com/dchest/cmac",
    commit = "62ff55a1048c485e83f1882466f535da624e944a",
)
go_repository(
    name = "com_github_go_ini_ini",
    importpath = "github.com/go-ini/ini",
    commit = "32e4c1e6bc4e7d0d8451aa6b75200d19e37a536a",
)
go_repository(
    name = "com_github_go_stack_stack",
    importpath = "github.com/go-stack/stack",
    commit = "100eb0c0a9c5b306ca2fb4f165df21d80ada4b82",
)
go_repository(
    name = "com_github_golang_mock",
    importpath = "github.com/golang/mock", # gomock
    commit = "c34cdb4725f4c3844d095133c6e40e448b86589b",
)
go_repository(
    name = "com_github_golang_protobuf",
    importpath = "github.com/golang/protobuf", # proto
    commit = "98fa357170587e470c5f27d3c3ea0947b71eb455",
)
go_repository(
    name = "com_github_google_go_cmp",
    importpath = "github.com/google/go-cmp", # cmp
    commit = "2248b49eaa8e1c8c0963ee77b40841adbc19d4ca",
)
go_repository(
    name = "com_github_google_gopacket",
    importpath = "github.com/google/gopacket",
    commit = "102d5ca2098cc070c7fdc9d7dbd504658bc92363",
)
go_repository(
    name = "com_github_hashicorp_golang_lru",
    importpath = "github.com/hashicorp/golang-lru",
    commit = "0fb14efe8c47ae851c0034ed7a448854d3d34cf3",
)
go_repository(
    name = "com_github_inconshreveable_log15",
    importpath = "github.com/inconshreveable/log15",
    commit = "944cbfb97b448e4f63f0bdb69c2850e3de1aeae9",
)
go_repository(
    name = "com_github_inconshreveable_mousetrap",
    importpath = "github.com/inconshreveable/mousetrap",
    commit = "76626ae9c91c4f2a10f34cad8ce83ea42c93bb75",
)
go_repository(
    name = "com_github_jtolds_gls",
    importpath = "github.com/jtolds/gls",
    commit = "8ddce2a84170772b95dd5d576c48d517b22cac63",
)
go_repository(
    name = "com_github_kisielk_gotool",
    importpath = "github.com/kisielk/gotool",
    commit = "80517062f582ea3340cd4baf70e86d539ae7d84d",
)
go_repository(
    name = "com_github_kormat_fmt15",
    importpath = "github.com/kormat/fmt15",
    commit = "ee69fecb2656a4de8ac47df338ad7e7f9e056dd5",
)
go_repository(
    name = "com_github_lucas_clemente_aes12",
    importpath = "github.com/lucas-clemente/aes12",
    commit = "cd47fb39b79f867c6e4e5cd39cf7abd799f71670",
)
go_repository(
    name = "com_github_lucas_clemente_quic_go",
    importpath = "github.com/lucas-clemente/quic-go",
    commit = "deffae864a3363cf4cd4a0030fc8106e16ec5723",
)
go_repository(
    name = "com_github_lucas_clemente_quic_go_certificates",
    importpath = "github.com/lucas-clemente/quic-go-certificates",
    commit = "d2f86524cced5186554df90d92529757d22c1cb6",
)
go_repository(
    name = "com_github_matm_gocov_html",
    importpath = "github.com/matm/gocov-html",
    commit = "f6dd0fd0ebc7c8cff8b24c0a585caeef250627a3",
)
go_repository(
    name = "com_github_mattn_go_colorable",
    importpath = "github.com/mattn/go-colorable",
    commit = "6c903ff4aa50920ca86087a280590b36b3152b9c",
)
go_repository(
    name = "com_github_mattn_go_isatty",
    importpath = "github.com/mattn/go-isatty",
    commit = "fc9e8d8ef48496124e79ae0df75490096eccf6fe",
)
go_repository(
    name = "com_github_mattn_go_sqlite3",
    importpath = "github.com/mattn/go-sqlite3",
    commit = "b3511bfdd742af558b54eb6160aca9446d762a19",
)
go_repository(
    name = "com_github_matttproud_golang_protobuf_extensions",
    importpath = "github.com/matttproud/golang_protobuf_extensions", # ext
    commit = "c12348ce28de40eed0136aa2b644d0ee0650e56c",
)
go_repository(
    name = "com_github_patrickmn_go_cache",
    importpath = "github.com/patrickmn/go-cache",
    commit = "7ac151875ffb48b9f3ccce9ea20f020b0c1596c8",
)
go_repository(
    name = "com_github_pavius_impi",
    importpath = "github.com/pavius/impi",
    commit = "c1cbdcb8df2b23af8530360d87ac9a7fabc48618",
)
go_repository(
    name = "com_github_pierrec_lz4",
    importpath = "github.com/pierrec/lz4",
    commit = "08c27939df1bd95e881e2c2367a749964ad1fceb",
)
go_repository(
    name = "com_github_pierrec_xxhash",
    importpath = "github.com/pierrec/xxHash", # xxhsum
    commit = "a0006b13c722f7f12368c00a3d3c2ae8a999a0c6",
)
go_repository(
    name = "com_github_prometheus_client_golang",
    importpath = "github.com/prometheus/client_golang", # prometheus
    commit = "abad2d1bd44235a26707c172eab6bca5bf2dbad3",
)
go_repository(
    name = "com_github_prometheus_client_model",
    importpath = "github.com/prometheus/client_model",
    commit = "fa8ad6fec33561be4280a8f0514318c79d7f6cb6",
)
go_repository(
    name = "com_github_prometheus_common",
    importpath = "github.com/prometheus/common", # model
    commit = "0b1957f9d949dfa3084171a6ec5642b38055276a",
)
go_repository(
    name = "com_github_prometheus_procfs",
    importpath = "github.com/prometheus/procfs",
    commit = "185b4288413d2a0dd0806f78c90dde719829e5ae",
)
go_repository(
    name = "com_github_smartystreets_assertions",
    importpath = "github.com/smartystreets/assertions",
    commit = "2063fd1cc7c975db70502811a34b06ad034ccdf2",
)
go_repository(
    name = "com_github_smartystreets_goconvey",
    importpath = "github.com/smartystreets/goconvey",
    commit = "a9793712606dd72b256bcbb0fad0858aa0e72d67",
    vcs = "git",
    remote = "https://github.com/kormat/goconvey.git",
)
go_repository(
    name = "com_github_songgao_water",
    importpath = "github.com/songgao/water",
    commit = "99d07fc117afd4d997bc5ebca77c241644ffe24a",
)
go_repository(
    name = "com_github_spf13_cobra",
    importpath = "github.com/spf13/cobra",
    commit = "cd30c2a7e91a1d63fd9a0027accf18a681e9d50b",
)
go_repository(
    name = "com_github_spf13_pflag",
    importpath = "github.com/spf13/pflag",
    commit = "1ce0cc6db4029d97571db82f85092fccedb572ce",
)
go_repository(
    name = "com_github_syndtr_gocapability",
    importpath = "github.com/syndtr/gocapability", # capability
    commit = "e7cb7fa329f456b3855136a2642b197bad7366ba",
)
go_repository(
    name = "com_github_vishvananda_netlink",
    importpath = "github.com/vishvananda/netlink",
    commit = "177f1ceba557262b3f1c3aba4df93a29199fb4eb",
)
go_repository(
    name = "com_github_vishvananda_netns",
    importpath = "github.com/vishvananda/netns",
    commit = "54f0e4339ce73702a0607f49922aaa1e749b418d",
)
go_repository(
    name = "org_golang_x_crypto",
    importpath = "golang.org/x/crypto", # acme
    commit = "8ac0e0d97ce45cd83d1d7243c060cb8461dda5e9",
)
go_repository(
    name = "org_golang_x_net",
    importpath = "golang.org/x/net", # ipv4
    commit = "c7086645de248775cbf2373cf5ca4d2fa664b8c1",
)
go_repository(
    name = "org_golang_x_sys",
    importpath = "golang.org/x/sys", # unix
    commit = "314a259e304ff91bd6985da2a7149bbf91237993",
)
go_repository(
    name = "org_golang_x_tools",
    importpath = "golang.org/x/tools", # cover
    commit = "5e2ae75eb72a62985e086eed33a5982a929e4fff",
)
go_repository(
    name = "in_gopkg_natefinch_lumberjack_v2",
    importpath = "gopkg.in/natefinch/lumberjack.v2",
    commit = "e21e5cbec0cd0861b9dc302736ad5666c529d93f",
)
go_repository(
    name = "in_gopkg_restruct_v1",
    importpath = "gopkg.in/restruct.v1",
    commit = "80ede2e57cc280052ab88753387703aa62475571",
)
go_repository(
    name = "in_gopkg_yaml_v2",
    importpath = "gopkg.in/yaml.v2",
    commit = "a5b47d31c556af34a302ce5d659e6fea44d90de0",
)
go_repository(
    name = "com_zombiezen_go_capnproto2",
    importpath = "zombiezen.com/go/capnproto2",
    commit = "659aba4018b61e5f07f6b90ff2abc5b300baccea",
)
go_repository(
    name = "com_github_jmhodges_bazel_gomock",
    importpath = "github.com/jmhodges/bazel_gomock",
    commit = "ff6c20a9b6978c52b88b7a1e2e55b3b86e26685b",
)

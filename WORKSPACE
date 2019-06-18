# Generic stuff for dealing with repositories.
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

# Bazel rules for Golang
git_repository(
    name = "io_bazel_rules_go",
    remote = "https://github.com/bazelbuild/rules_go.git",
    tag = "0.18.6",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_download_sdk", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_download_sdk(
    name = "go_sdk",
    sdks = {
        "linux_amd64": ("go1.11.5.linux-amd64.tar.gz", "ff54aafedff961eb94792487e827515da683d61a5f9482f668008832631e5d25"),
    },
)

go_register_toolchains(nogo = "@//:nogo")

# Gazelle
http_archive(
    name = "bazel_gazelle",
    urls = ["https://github.com/bazelbuild/bazel-gazelle/releases/download/0.17.0/bazel-gazelle-0.17.0.tar.gz"],
    sha256 = "3c681998538231a2d24d0c07ed5a7658cb72bfb5fd4bf9911157c0e9ac6a2687",
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

# Docker rules
http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "aed1c249d4ec8f703edddf35cbe9dfaca0b5f5ea6e4cd9e83e99f3b0d1136c3d",
    strip_prefix = "rules_docker-0.7.0",
    urls = ["https://github.com/bazelbuild/rules_docker/archive/v0.7.0.tar.gz"],
)

load("@io_bazel_rules_docker//repositories:repositories.bzl", container_repositories = "repositories")

container_repositories()

# Distroless
git_repository(
    name = "distroless",
    commit = "0a3d642379d577a09225f1275e5c96e336472dfc",
    remote = "https://github.com/GoogleContainerTools/distroless.git",
)

# Debian packages to install in containers
load("@distroless//package_manager:package_manager.bzl", "package_manager_repositories")
load("@distroless//package_manager:dpkg.bzl", "dpkg_src", "dpkg_list")

package_manager_repositories()

dpkg_src(
    name = "debian_stretch",
    arch = "amd64",
    distro = "stretch",
    sha256 = "4cb2fac3e32292613b92d3162e99eb8a1ed7ce47d1b142852b0de3092b25910c",
    snapshot = "20180406T095535Z",
    url = "http://snapshot.debian.org/archive",
)

dpkg_list(
    name = "package_bundle",
    packages = [
        "libc6",
        "libcap2",
        "libcap2-bin",
        "libgcc1",
        "libstdc++6",
        # These are needed by distroless.
        "base-files",
        "ca-certificates",
        "libssl1.1",
        "netbase",
        "openssl",
        "tzdata",
    ],
    sources = [
        "@debian_stretch//file:Packages.json",
    ],
)

# su-exec (used in app docker images)
git_repository(
    name = "com_github_anapaya_su_exec",
    commit = "d7253c2eb8987067834bc7d2fb7bd0c7958ce1ff",
    remote = "https://github.com/Anapaya/su-exec.git",
)

# Busybox (used in debug docker images)
http_file(
    name = "busybox",
    executable = True,
    sha256 = "b51b9328eb4e60748912e1c1867954a5cf7e9d5294781cae59ce225ed110523c",
    urls = ["https://busybox.net/downloads/binaries/1.27.1-i686/busybox"],
)

# Note the comments in the rules below. These point to an arbitrary directory within the repo
# that contains Go files. The comment is not needed if the root directory contains Go files.
# To understand how it works see tools/fetch.sh
# Dependencies
go_repository(
    name = "com_github_burntsushi_toml",
    commit = "a368813c5e648fee92e5f6c30e3944ff9d5e8895",
    importpath = "github.com/BurntSushi/toml",
)

go_repository(
    name = "com_github_jeanmertz_lll",
    commit = "c7683829ec0c1f892b2d0468356597573afafb03",
    importpath = "github.com/JeanMertz/lll",
)

go_repository(
    name = "com_github_aead_chacha20",
    commit = "e2538746bfea853aaa589feb8ec46bd46ee78f86",
    importpath = "github.com/aead/chacha20",
)

go_repository(
    name = "com_github_alexflint_go_arg",
    commit = "f7c0423bd11ee80ab81d25c6d46f492998af8547",
    importpath = "github.com/alexflint/go-arg",
)

go_repository(
    name = "com_github_alexflint_go_scalar",
    commit = "e80c3b7ed292b052c7083b6fd7154a8422c33f65",
    importpath = "github.com/alexflint/go-scalar",
)

go_repository(
    name = "com_github_antlr_antlr4",
    commit = "d4d7e3d3bc3b65bb00579fe826834a9263fa45e6",
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
    name = "com_github_bifurcation_mint",
    commit = "198357931e6129b810c9c77c12e0dd754846170c",
    importpath = "github.com/bifurcation/mint",
)

go_repository(
    name = "com_github_client9_misspell",
    commit = "c0b55c8239520f6b5aa15a0207ca8b28027ba49e",
    importpath = "github.com/client9/misspell",
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
    name = "com_github_golang_protobuf",
    commit = "98fa357170587e470c5f27d3c3ea0947b71eb455",
    importpath = "github.com/golang/protobuf",  # proto
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
    commit = "8ddce2a84170772b95dd5d576c48d517b22cac63",
    importpath = "github.com/jtolds/gls",
)

go_repository(
    name = "com_github_kisielk_gotool",
    commit = "80517062f582ea3340cd4baf70e86d539ae7d84d",
    importpath = "github.com/kisielk/gotool",
)

go_repository(
    name = "com_github_kormat_fmt15",
    commit = "ee69fecb2656a4de8ac47df338ad7e7f9e056dd5",
    importpath = "github.com/kormat/fmt15",
)

go_repository(
    name = "com_github_lucas_clemente_aes12",
    commit = "cd47fb39b79f867c6e4e5cd39cf7abd799f71670",
    importpath = "github.com/lucas-clemente/aes12",
)

go_repository(
    name = "com_github_lucas_clemente_quic_go",
    commit = "fd7246d7ed6eeb79eb4dc8b7b1bfa8a13047105a",
    importpath = "github.com/lucas-clemente/quic-go",
)

go_repository(
    name = "com_github_lucas_clemente_quic_go_certificates",
    commit = "d2f86524cced5186554df90d92529757d22c1cb6",
    importpath = "github.com/lucas-clemente/quic-go-certificates",
)

go_repository(
    name = "com_github_matm_gocov_html",
    commit = "f6dd0fd0ebc7c8cff8b24c0a585caeef250627a3",
    importpath = "github.com/matm/gocov-html",
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
    commit = "7ac151875ffb48b9f3ccce9ea20f020b0c1596c8",
    importpath = "github.com/patrickmn/go-cache",
)

go_repository(
    name = "com_github_pavius_impi",
    commit = "c1cbdcb8df2b23af8530360d87ac9a7fabc48618",
    importpath = "github.com/pavius/impi",
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
    commit = "abad2d1bd44235a26707c172eab6bca5bf2dbad3",
    importpath = "github.com/prometheus/client_golang",  # prometheus
)

go_repository(
    name = "com_github_prometheus_client_model",
    commit = "fa8ad6fec33561be4280a8f0514318c79d7f6cb6",
    importpath = "github.com/prometheus/client_model",
)

go_repository(
    name = "com_github_prometheus_common",
    commit = "0b1957f9d949dfa3084171a6ec5642b38055276a",
    importpath = "github.com/prometheus/common",  # model
)

go_repository(
    name = "com_github_prometheus_procfs",
    commit = "185b4288413d2a0dd0806f78c90dde719829e5ae",
    importpath = "github.com/prometheus/procfs",
)

go_repository(
    name = "com_github_smartystreets_assertions",
    commit = "2063fd1cc7c975db70502811a34b06ad034ccdf2",
    importpath = "github.com/smartystreets/assertions",
)

go_repository(
    name = "com_github_smartystreets_goconvey",
    commit = "a9793712606dd72b256bcbb0fad0858aa0e72d67",
    importpath = "github.com/smartystreets/goconvey",
    vcs = "git",
    remote = "https://github.com/kormat/goconvey.git",
)

go_repository(
    name = "com_github_songgao_water",
    commit = "99d07fc117afd4d997bc5ebca77c241644ffe24a",
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
    name = "org_golang_x_net",
    commit = "c7086645de248775cbf2373cf5ca4d2fa664b8c1",
    importpath = "golang.org/x/net",  # ipv4
)

go_repository(
    name = "org_golang_x_sys",
    commit = "314a259e304ff91bd6985da2a7149bbf91237993",
    importpath = "golang.org/x/sys",  # unix
)

go_repository(
    name = "org_golang_x_tools",
    commit = "5e2ae75eb72a62985e086eed33a5982a929e4fff",
    importpath = "golang.org/x/tools",  # cover
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
    commit = "a5b47d31c556af34a302ce5d659e6fea44d90de0",
    importpath = "gopkg.in/yaml.v2",
)

go_repository(
    name = "com_zombiezen_go_capnproto2",
    commit = "659aba4018b61e5f07f6b90ff2abc5b300baccea",
    importpath = "zombiezen.com/go/capnproto2",
)

go_repository(
    name = "com_github_jmhodges_bazel_gomock",
    commit = "ff6c20a9b6978c52b88b7a1e2e55b3b86e26685b",
    importpath = "github.com/jmhodges/bazel_gomock",
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

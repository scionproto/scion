load("@bazel_gazelle//:deps.bzl", "go_repository")

def tool_deps():
    go_repository(
        name = "com_github_jeanmertz_lll",
        commit = "c7683829ec0c1f892b2d0468356597573afafb03",
        importpath = "github.com/JeanMertz/lll",
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
        name = "com_github_client9_misspell",
        commit = "c0b55c8239520f6b5aa15a0207ca8b28027ba49e",
        importpath = "github.com/client9/misspell",
    )

    go_repository(
        name = "com_github_kisielk_gotool",
        commit = "80517062f582ea3340cd4baf70e86d539ae7d84d",
        importpath = "github.com/kisielk/gotool",
    )

    go_repository(
        name = "com_github_oncilla_gochecks",
        commit = "954a3ef2d56471a40cc0c6fcb86e1e9a3b21949e",
        importpath = "github.com/oncilla/gochecks",  # serrorscheck
        build_file_generation = "off",
    )

    go_repository(
        name = "com_github_oncilla_ineffassign",
        commit = "198c6a326229fbe8a5803f701ea9da06bc8c1776",
        importpath = "github.com/Oncilla/ineffassign",
    )

    go_repository(
        name = "com_github_pavius_impi",
        commit = "c1cbdcb8df2b23af8530360d87ac9a7fabc48618",
        importpath = "github.com/pavius/impi",
    )

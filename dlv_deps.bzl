load("@bazel_gazelle//:deps.bzl", "go_repository")

def dlv_repositories():
    go_repository(
        name = "com_github_cosiner_argv",
        importpath = "github.com/cosiner/argv",
        sum = "h1:BVDiEL32lwHukgJKP87btEPenzrrHUjajs/8yzaqcXg=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_cpuguy83_go_md2man",
        importpath = "github.com/cpuguy83/go-md2man",
        sum = "h1:BSKMNlYxDvnunlTymqtgONjNnaRV1sTpcovwwjF22jk=",
        version = "v1.0.10",
    )
    go_repository(
        name = "com_github_go_delve_delve",
        importpath = "github.com/go-delve/delve",
        sum = "h1:gQsRvFdR0BGk19NROQZsAv6iG4w5QIZoJlxJeEUBb0c=",
        version = "v1.5.0",
    )
    go_repository(
        name = "com_github_google_go_dap",
        importpath = "github.com/google/go-dap",
        sum = "h1:whjIGQRumwbR40qRU7CEKuFLmePUUc2s4Nt9DoXXxWk=",
        version = "v0.2.0",
    )
    go_repository(
        name = "com_github_peterh_liner",
        importpath = "github.com/peterh/liner",
        sum = "h1:8uaXtUkxiy+T/zdLWuxa/PG4so0TPZDZfafFNNSaptE=",
        version = "v0.0.0-20170317030525-88609521dc4b",
    )
    go_repository(
        name = "io_rsc_pdf",
        importpath = "rsc.io/pdf",
        sum = "h1:k1MczvYDUvJBe93bYd7wrZLLUEcLZAuF824/I4e5Xr4=",
        version = "v0.1.1",
    )
    go_repository(
        name = "net_starlark_go",
        importpath = "go.starlark.net",
        sum = "h1:lkYv5AKwvvduv5XWP6szk/bvvgO6aDeUujhZQXIFTes=",
        version = "v0.0.0-20190702223751-32f345186213",
    )
    go_repository(
        name = "org_golang_x_arch",
        importpath = "golang.org/x/arch",
        sum = "h1:QlVATYS7JBoZMVaf+cNjb90WD/beKVHnIxFKT4QaHVI=",
        version = "v0.0.0-20190927153633-4e8777c89be4",
    )

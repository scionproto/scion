# Generated from go.mod by gazelle. DO NOT EDIT
load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_deps():
    go_repository(
        name = "com_github_alecthomas_template",
        importpath = "github.com/alecthomas/template",
        sum = "h1:cAKDfWh5VpdgMhJosfJnn5/FoN2SRZ4p7fJNX58YPaU=",
        version = "v0.0.0-20160405071501-a0175ee3bccc",
    )
    go_repository(
        name = "com_github_alecthomas_units",
        importpath = "github.com/alecthomas/units",
        sum = "h1:qet1QNfXsQxTZqLG4oE62mJzwPIB8+Tee4RNCL9ulrY=",
        version = "v0.0.0-20151022065526-2efee857e7cf",
    )
    go_repository(
        name = "com_github_antlr_antlr4",
        importpath = "github.com/antlr/antlr4",
        sum = "h1:yxMh4HIdsSh2EqxUESWvzszYMNzOugRyYCeohfwNULM=",
        version = "v0.0.0-20181218183524-be58ebffde8e",
    )
    go_repository(
        name = "com_github_beorn7_perks",
        importpath = "github.com/beorn7/perks",
        sum = "h1:VlbKKnNfV8bJzeqoa4cOKqO6bYr3WgKZxO8Z16+hsOM=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_buildkite_go_buildkite",
        importpath = "github.com/buildkite/go-buildkite",
        sum = "h1:wELXQi9HWcUzDcns3k5p3Qj9hLN6jrnO8uwcC6ba/ac=",
        version = "v2.2.1-0.20190413010238-568b6651b687+incompatible",
    )
    go_repository(
        name = "com_github_burntsushi_toml",
        importpath = "github.com/BurntSushi/toml",
        sum = "h1:WXkYYl6Yr3qBf1K79EBnL4mak0OimBfB0XUf9Vl28OQ=",
        version = "v0.3.1",
    )
    go_repository(
        name = "com_github_cenkalti_backoff",
        importpath = "github.com/cenkalti/backoff",
        sum = "h1:tNowT99t7UNflLxfYYSlKYsBpXdEet03Pg2g16Swow4=",
        version = "v2.2.1+incompatible",
    )
    go_repository(
        name = "com_github_cheekybits_genny",
        importpath = "github.com/cheekybits/genny",
        sum = "h1:a1zrFsLFac2xoM6zG1u72DWJwZG3ayttYLfmLbxVETk=",
        version = "v0.0.0-20170328200008-9127e812e1e9",
    )
    go_repository(
        name = "com_github_cloudflare_sidh",
        importpath = "github.com/cloudflare/sidh",
        sum = "h1:pqwbJdj1rgMkE38tDSNnP97wdMYHzV+Lt/aLL2qw2LQ=",
        version = "v0.0.0-20181111220428-fc8e6378752b",
    )
    go_repository(
        name = "com_github_codahale_hdrhistogram",
        importpath = "github.com/codahale/hdrhistogram",
        sum = "h1:qMd81Ts1T2OTKmB4acZcyKaMtRnY5Y44NuXGX2GFJ1w=",
        version = "v0.0.0-20161010025455-3a0bb77429bd",
    )
    go_repository(
        name = "com_github_davecgh_go_spew",
        importpath = "github.com/davecgh/go-spew",
        sum = "h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_dchest_cmac",
        importpath = "github.com/dchest/cmac",
        sum = "h1:qoavXEzRRUfup81LsDQv4fnUQbLyorpPz6WxiwdiU7A=",
        version = "v0.0.0-20150527144652-62ff55a1048c",
    )
    go_repository(
        name = "com_github_fsnotify_fsnotify",
        importpath = "github.com/fsnotify/fsnotify",
        sum = "h1:IXs+QLmnXW2CcXuY+8Mzv/fWEsPGWxqefPtCP5CnV9I=",
        version = "v1.4.7",
    )
    go_repository(
        name = "com_github_go_kit_kit",
        importpath = "github.com/go-kit/kit",
        sum = "h1:Wz+5lgoB0kkuqLEc6NVmwRknTKP6dTGbSqvhZtBI/j0=",
        version = "v0.8.0",
    )
    go_repository(
        name = "com_github_go_logfmt_logfmt",
        importpath = "github.com/go-logfmt/logfmt",
        sum = "h1:MP4Eh7ZCb31lleYCFuwm0oe4/YGak+5l1vA2NOE80nA=",
        version = "v0.4.0",
    )
    go_repository(
        name = "com_github_go_stack_stack",
        importpath = "github.com/go-stack/stack",
        sum = "h1:5SgMzNM5HxrEjV0ww2lTmX6E2Izsfxas4+YHWRs3Lsk=",
        version = "v1.8.0",
    )
    go_repository(
        name = "com_github_gogo_protobuf",
        importpath = "github.com/gogo/protobuf",
        sum = "h1:72R+M5VuhED/KujmZVcIquuo8mBgX4oVda//DQb3PXo=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_golang_mock",
        importpath = "github.com/golang/mock",
        sum = "h1:T7BbTPTeAnatnqlwwWt+77l0YF8UBKcWf1GEK5M9YQ8=",
        version = "v1.2.1-0.20190329180013-73dc87cad333",
    )
    go_repository(
        name = "com_github_golang_protobuf",
        importpath = "github.com/golang/protobuf",
        sum = "h1:6nsPYzhq5kReh6QImI3k5qWzO4PEbvbIW2cwSfR/6xs=",
        version = "v1.3.2",
    )
    go_repository(
        name = "com_github_google_go_cmp",
        importpath = "github.com/google/go-cmp",
        sum = "h1:crn/baboCvb5fXaQ0IJ1SGTsTVrWpDsCWC8EGETZijY=",
        version = "v0.3.0",
    )
    go_repository(
        name = "com_github_google_go_querystring",
        importpath = "github.com/google/go-querystring",
        sum = "h1:Avad62mreCc9la5buHvHZXbvsY+GPYUVjd8xsi48FYY=",
        version = "v1.0.1-0.20190318165438-c8c88dbee036",
    )
    go_repository(
        name = "com_github_google_gofuzz",
        importpath = "github.com/google/gofuzz",
        sum = "h1:A8PeW59pxE9IoFRqBp37U+mSNaQoZ46F1f0f863XSXw=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_google_gopacket",
        importpath = "github.com/google/gopacket",
        sum = "h1:eR3RuANqlK0CQoHJxUdXQNsco+gJykcti01+wqBCuPs=",
        version = "v1.1.16-0.20190123011826-102d5ca2098c",
    )
    go_repository(
        name = "com_github_gopherjs_gopherjs",
        importpath = "github.com/gopherjs/gopherjs",
        sum = "h1:EGx4pi6eqNxGaHF6qqu48+N2wcFQ5qg5FXgOdqsJ5d8=",
        version = "v0.0.0-20181017120253-0766667cb4d1",
    )
    go_repository(
        name = "com_github_hpcloud_tail",
        importpath = "github.com/hpcloud/tail",
        sum = "h1:nfCOvKYfkgYP8hkirhJocXT2+zOD8yUNjXaWfTlyFKI=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_iancoleman_strcase",
        importpath = "github.com/iancoleman/strcase",
        sum = "h1:ECW73yc9MY7935nNYXUkK7Dz17YuSUI9yqRqYS8aBww=",
        version = "v0.0.0-20190422225806-e506e3ef7365",
    )
    go_repository(
        name = "com_github_inconshreveable_log15",
        importpath = "github.com/inconshreveable/log15",
        sum = "h1:KyyrbB0Qcnv9SwgbcYQKK6L191WKsIq2hiYj6lsrcTU=",
        version = "v0.0.0-20161013181240-944cbfb97b44",
    )
    go_repository(
        name = "com_github_inconshreveable_mousetrap",
        importpath = "github.com/inconshreveable/mousetrap",
        sum = "h1:Z8tu5sraLXCXIcARxBp/8cbvlwVa7Z1NHg9XEKhtSvM=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_json_iterator_go",
        importpath = "github.com/json-iterator/go",
        sum = "h1:KfgG9LzI+pYjr4xvmz/5H4FXjokeP+rlHLhv3iH62Fo=",
        version = "v1.1.7",
    )
    go_repository(
        name = "com_github_jtolds_gls",
        importpath = "github.com/jtolds/gls",
        sum = "h1:xdiiI2gbIgH/gLH7ADydsJ1uDOEzR8yvV7C0MuV77Wo=",
        version = "v4.20.0+incompatible",
    )
    go_repository(
        name = "com_github_julienschmidt_httprouter",
        importpath = "github.com/julienschmidt/httprouter",
        sum = "h1:TDTW5Yz1mjftljbcKqRcrYhd4XeOoI98t+9HbQbYf7g=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_konsorten_go_windows_terminal_sequences",
        importpath = "github.com/konsorten/go-windows-terminal-sequences",
        sum = "h1:mweAR1A6xJ3oS2pRaGiHgQ4OO8tzTaLawm8vnODuwDk=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_kormat_fmt15",
        importpath = "github.com/kormat/fmt15",
        sum = "h1:aG3mi6+atPavBL5PM/s0XqiRuJ2n08aEY9xza16XGTo=",
        version = "v0.0.0-20181112140556-ee69fecb2656",
    )
    go_repository(
        name = "com_github_kr_logfmt",
        importpath = "github.com/kr/logfmt",
        sum = "h1:T+h1c/A9Gawja4Y9mFVWj2vyii2bbUNDw3kt9VxK2EY=",
        version = "v0.0.0-20140226030751-b84e30acd515",
    )
    go_repository(
        name = "com_github_kylelemons_godebug",
        importpath = "github.com/kylelemons/godebug",
        sum = "h1:RPNrshWIDI6G2gRW9EHilWtl7Z6Sb1BR0xunSBf0SNc=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_lucas_clemente_quic_go",
        importpath = "github.com/lucas-clemente/quic-go",
        sum = "h1:Y07tY5Q2/7WwkwZHxYlQC4mQeD1kM6BQLk/6S64KHY4=",
        version = "v0.7.1-0.20190212114006-fd7246d7ed6e",
    )
    go_repository(
        name = "com_github_marten_seemann_qtls",
        importpath = "github.com/marten-seemann/qtls",
        sum = "h1:7Fx1paF8onfPhcIMlwgznBklz62TrCZjOjoBbUod/3Y=",
        version = "v0.0.0-20190207043627-591c71538704",
    )
    go_repository(
        name = "com_github_mattn_go_colorable",
        importpath = "github.com/mattn/go-colorable",
        sum = "h1:snbPLB8fVfU9iwbbo30TPtbLRzwWu6aJS6Xh4eaaviA=",
        version = "v0.1.4",
    )
    go_repository(
        name = "com_github_mattn_go_isatty",
        importpath = "github.com/mattn/go-isatty",
        sum = "h1:HLtExJ+uU2HOZ+wI0Tt5DtUDrx8yhUqDcp7fYERX4CE=",
        version = "v0.0.8",
    )
    go_repository(
        name = "com_github_mattn_go_sqlite3",
        importpath = "github.com/mattn/go-sqlite3",
        sum = "h1:CxNxKbYu7Gc9ATyoSyjSLzf9wEryOLLhU5YCOR6x6MU=",
        version = "v1.9.1-0.20180719091609-b3511bfdd742",
    )
    go_repository(
        name = "com_github_matttproud_golang_protobuf_extensions",
        importpath = "github.com/matttproud/golang_protobuf_extensions",
        sum = "h1:4hp9jkHxhMHkqkrB3Ix0jegS5sx/RkqARlsWZ6pIwiU=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_modern_go_concurrent",
        importpath = "github.com/modern-go/concurrent",
        sum = "h1:TRLaZ9cD/w8PVh93nsPXa1VrQ6jlwL5oN8l14QlcNfg=",
        version = "v0.0.0-20180306012644-bacd9c7ef1dd",
    )
    go_repository(
        name = "com_github_modern_go_reflect2",
        importpath = "github.com/modern-go/reflect2",
        sum = "h1:9f412s+6RmYXLWZSEzVVgPGK7C2PphHj5RJrvfx9AWI=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_mwitkow_go_conntrack",
        importpath = "github.com/mwitkow/go-conntrack",
        sum = "h1:F9x/1yl3T2AeKLr2AMdilSD8+f9bvMnNN8VS5iDtovc=",
        version = "v0.0.0-20161129095857-cc309e4a2223",
    )
    go_repository(
        name = "com_github_onsi_ginkgo",
        importpath = "github.com/onsi/ginkgo",
        sum = "h1:OoxbjfXVZyod1fmWYhI7SEyaD8B00ynP3T+D5GiyHOY=",
        version = "v1.10.3",
    )
    go_repository(
        name = "com_github_onsi_gomega",
        importpath = "github.com/onsi/gomega",
        sum = "h1:K0jcRCwNQM3vFGh1ppMtDh/+7ApJrjldlX8fA0jDTLQ=",
        version = "v1.7.1",
    )
    go_repository(
        name = "com_github_opentracing_opentracing_go",
        importpath = "github.com/opentracing/opentracing-go",
        sum = "h1:pWlfV3Bxv7k65HYwkikxat0+s3pV4bsqf19k25Ur8rU=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_patrickmn_go_cache",
        importpath = "github.com/patrickmn/go-cache",
        sum = "h1:MUIwjEiAMYk8zkXXUQeb5itrXF+HpS2pfxNsA2a7AiY=",
        version = "v2.1.1-0.20180815053127-5633e0862627+incompatible",
    )
    go_repository(
        name = "com_github_philhofer_fwd",
        importpath = "github.com/philhofer/fwd",
        sum = "h1:UbZqGr5Y38ApvM/V/jEljVxwocdweyH+vmYvRPBnbqQ=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_pkg_errors",
        importpath = "github.com/pkg/errors",
        sum = "h1:PCj9X21C4pet4sEcElTfAi6LSl5ShkjE8doieLc+cbU=",
        version = "v0.8.2-0.20190227000051-27936f6d90f9",
    )
    go_repository(
        name = "com_github_pmezard_go_difflib",
        importpath = "github.com/pmezard/go-difflib",
        sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_prometheus_client_golang",
        importpath = "github.com/prometheus/client_golang",
        sum = "h1:BQ53HtBmfOitExawJ6LokA4x8ov/z0SYYb0+HxJfRI8=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_prometheus_client_model",
        importpath = "github.com/prometheus/client_model",
        sum = "h1:gQz4mCbXsO+nc9n1hCxHcGA3Zx3Eo+UHZoInFGUIXNM=",
        version = "v0.0.0-20190812154241-14fe0d1b01d4",
    )
    go_repository(
        name = "com_github_prometheus_common",
        importpath = "github.com/prometheus/common",
        sum = "h1:kRhiuYSXR3+uv2IbVbZhUxK5zVD/2pp3Gd2PpvPkpEo=",
        version = "v0.6.0",
    )
    go_repository(
        name = "com_github_prometheus_procfs",
        importpath = "github.com/prometheus/procfs",
        sum = "h1:CTwfnzjQ+8dS6MhHHu4YswVAD99sL2wjPqP+VkURmKE=",
        version = "v0.0.3",
    )
    go_repository(
        name = "com_github_sergi_go_diff",
        importpath = "github.com/sergi/go-diff",
        sum = "h1:tB9NOR21++IjLyVx3/PCPhWMwqGNCMQEH96A6dMZ/gc=",
        version = "v1.0.1-0.20180205163309-da645544ed44",
    )
    go_repository(
        name = "com_github_sirupsen_logrus",
        importpath = "github.com/sirupsen/logrus",
        sum = "h1:juTguoYk5qI21pwyTXY3B3Y5cOTH3ZUyZCg1v/mihuo=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_smartystreets_assertions",
        importpath = "github.com/smartystreets/assertions",
        sum = "h1:zE9ykElWQ6/NYmHa3jpm/yHnI4xSofP+UP6SpjHcSeM=",
        version = "v0.0.0-20180927180507-b2de0cb4f26d",
    )
    go_repository(
        name = "com_github_smartystreets_goconvey",
        importpath = "github.com/smartystreets/goconvey",
        replace = "github.com/kormat/goconvey",
        sum = "h1:NMGRuyMGEPkT+2ll1+M00ubrzqHa4Kfboygqql2mcgA=",
        version = "v0.0.0-20191113114839-63cc4eee0dbc",
    )
    go_repository(
        name = "com_github_songgao_water",
        importpath = "github.com/songgao/water",
        sum = "h1:+y4hCMc/WKsDbAPsOQZgBSaSZ26uh2afyaWeVg/3s/c=",
        version = "v0.0.0-20190725173103-fd331bda3f4b",
    )
    go_repository(
        name = "com_github_spf13_cobra",
        importpath = "github.com/spf13/cobra",
        sum = "h1:fkxjXeX1GqxICegQuav3Fpff2VNAMfqaPWZvI+dRqa0=",
        version = "v0.0.3-0.20180408161736-cd30c2a7e91a",
    )
    go_repository(
        name = "com_github_spf13_pflag",
        importpath = "github.com/spf13/pflag",
        sum = "h1:PzXGtoglK0gKAmoFi5ec8tZKKnTTxJM+3i7w/qw+Hf0=",
        version = "v1.0.1-0.20180403115518-1ce0cc6db402",
    )
    go_repository(
        name = "com_github_stretchr_objx",
        importpath = "github.com/stretchr/objx",
        sum = "h1:2vfRuCMp5sSVIDSqO8oNnWJq7mPa6KVP3iPIwFBuy8A=",
        version = "v0.1.1",
    )
    go_repository(
        name = "com_github_stretchr_testify",
        importpath = "github.com/stretchr/testify",
        sum = "h1:Ko2LQMrRU+Oy/+EDBwX7eZ2jp3C47eDBB8EIhKTun+I=",
        version = "v1.3.1-0.20190311161405-34c6fa2dc709",
    )
    go_repository(
        name = "com_github_syndtr_gocapability",
        importpath = "github.com/syndtr/gocapability",
        sum = "h1:w58e6FAOMd+rUgOfhaBb+ZVOQIOfUkpv5AAQVmf6hsI=",
        version = "v0.0.0-20160928074757-e7cb7fa329f4",
    )
    go_repository(
        name = "com_github_tinylib_msgp",
        importpath = "github.com/tinylib/msgp",
        sum = "h1:9fQd+ICuRIu/ue4vxJZu6/LzxN0HwMds2nq/0cFvxHU=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_uber_jaeger_client_go",
        importpath = "github.com/uber/jaeger-client-go",
        sum = "h1:HgqpYBng0n7tLJIlyT4kPCIv5XgCsF+kai1NnnrJzEU=",
        version = "v2.20.1+incompatible",
    )
    go_repository(
        name = "com_github_uber_jaeger_lib",
        importpath = "github.com/uber/jaeger-lib",
        sum = "h1:iMSCV0rmXEogjNWPh2D0xk9YVKvrtGoHJNe9ebLu/pw=",
        version = "v2.0.0+incompatible",
    )
    go_repository(
        name = "com_github_vishvananda_netlink",
        importpath = "github.com/vishvananda/netlink",
        sum = "h1:rg73JByvxSA/EIL/nVpTcVKP2DKy4Jw5bNJ+DxD4B+U=",
        version = "v0.0.0-20170924180554-177f1ceba557",
    )
    go_repository(
        name = "com_github_vishvananda_netns",
        importpath = "github.com/vishvananda/netns",
        sum = "h1:n630V+sEHbl2OrlWFxLoMoGPnUuniQ9eDvUaEmUdXaY=",
        version = "v0.0.0-20170219233438-54f0e4339ce7",
    )
    go_repository(
        name = "com_zombiezen_go_capnproto2",
        importpath = "zombiezen.com/go/capnproto2",
        sum = "h1:oaUsHxHA/DGY+XtWA4i5FLMxwWheqW21Az6xSLS1OzY=",
        version = "v0.0.0-20190813022230-ddfb9bb855fa",
    )
    go_repository(
        name = "in_gopkg_alecthomas_kingpin_v2",
        importpath = "gopkg.in/alecthomas/kingpin.v2",
        sum = "h1:jMFz6MfLP0/4fUyZle81rXUoxOBFi19VUFKVDOQfozc=",
        version = "v2.2.6",
    )
    go_repository(
        name = "in_gopkg_check_v1",
        importpath = "gopkg.in/check.v1",
        sum = "h1:yhCVgyC4o1eVCa2tZl7eS0r+SDo693bJlVdllGtEeKM=",
        version = "v0.0.0-20161208181325-20d25e280405",
    )
    go_repository(
        name = "in_gopkg_fsnotify_v1",
        importpath = "gopkg.in/fsnotify.v1",
        sum = "h1:xOHLXZwVvI9hhs+cLKq5+I5onOuwQLhQwiu63xxlHs4=",
        version = "v1.4.7",
    )
    go_repository(
        name = "in_gopkg_natefinch_lumberjack_v2",
        importpath = "gopkg.in/natefinch/lumberjack.v2",
        sum = "h1:AFxeG48hTWHhDTQDk/m2gorfVHUEa9vo3tp3D7TzwjI=",
        version = "v2.0.0-20170531160350-a96e63847dc3",
    )
    go_repository(
        name = "in_gopkg_restruct_v1",
        importpath = "gopkg.in/restruct.v1",
        sum = "h1:pqzOumCQ6icMR4sIIYRe2w7xCERvcPOFx22W9jSRsWg=",
        version = "v1.0.0-20151213023948-80ede2e57cc2",
    )
    go_repository(
        name = "in_gopkg_tomb_v1",
        importpath = "gopkg.in/tomb.v1",
        sum = "h1:uRGJdciOHaEIrze2W8Q3AKkepLTh2hOroT7a+7czfdQ=",
        version = "v1.0.0-20141024135613-dd632973f1e7",
    )
    go_repository(
        name = "in_gopkg_yaml_v2",
        importpath = "gopkg.in/yaml.v2",
        sum = "h1:/eiJrUcujPVeJ3xlSWaiNi3uSVmDGBK1pDHUHAnao1I=",
        version = "v2.2.4",
    )
    go_repository(
        name = "org_golang_google_appengine",
        importpath = "google.golang.org/appengine",
        sum = "h1:/wp5JvzpHIxhs/dumFmF7BXTf3Z+dd4uXta4kVyO508=",
        version = "v1.4.0",
    )
    go_repository(
        name = "org_golang_x_crypto",
        importpath = "golang.org/x/crypto",
        sum = "h1:VklqNMn3ovrHsnt90PveolxSbWFaJdECFbxSq0Mqo2M=",
        version = "v0.0.0-20190308221718-c2843e01d9a2",
    )
    go_repository(
        name = "org_golang_x_lint",
        importpath = "golang.org/x/lint",
        sum = "h1:5hukYrvBGR8/eNkX5mdUezrA6JiaEZDtJb9Ei+1LlBs=",
        version = "v0.0.0-20190930215403-16217165b5de",
    )
    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net",
        sum = "h1:QPlSTtPE2k6PZPasQUbzuK3p9JbS+vMXYVto8g/yrsg=",
        version = "v0.0.0-20191105084925-a882066a44e0",
    )
    go_repository(
        name = "org_golang_x_sync",
        importpath = "golang.org/x/sync",
        sum = "h1:8gQV6CLnAEikrhgkHFbMAEhagSSnXWGV915qUMm9mrU=",
        version = "v0.0.0-20190423024810-112230192c58",
    )
    go_repository(
        name = "org_golang_x_sys",
        importpath = "golang.org/x/sys",
        sum = "h1:4y9KwBHBgBNwDbtu44R5o1fdOCQUEXhbk/P4A9WmJq0=",
        version = "v0.0.0-20190801041406-cbf593c0f2f3",
    )
    go_repository(
        name = "org_golang_x_text",
        importpath = "golang.org/x/text",
        sum = "h1:g61tztE5qeGQ89tm6NTjjM9VPIm088od1l6aSorWRWg=",
        version = "v0.3.0",
    )
    go_repository(
        name = "org_golang_x_tools",
        importpath = "golang.org/x/tools",
        sum = "h1:IGkKhmfzcztjm6gYkykvu/NiS8kaqbCWAEWWAyf8J5U=",
        version = "v0.0.0-20191029041327-9cc4af7d6b2c",
    )
    go_repository(
        name = "org_golang_x_xerrors",
        importpath = "golang.org/x/xerrors",
        sum = "h1:9zdDQZ7Thm29KFXgAX/+yaf3eVbP7djjWp/dXAppNCc=",
        version = "v0.0.0-20190717185122-a985d3407aa7",
    )
    go_repository(
        name = "org_uber_go_atomic",
        importpath = "go.uber.org/atomic",
        sum = "h1:rsqfU5vBkVknbhUGbAUwQKR2H4ItV8tjJ+6kJX4cxHM=",
        version = "v1.5.1",
    )

# Generated from go.mod by gazelle. DO NOT EDIT
load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_deps():
    go_repository(
        name = "co_honnef_go_tools",
        importpath = "honnef.co/go/tools",
        sum = "h1:3JgtbtFHMiCmsznwGVTUWbgGov+pVqnlf1dEJTNAXeM=",
        version = "v0.0.1-2019.2.3",
    )
    go_repository(
        name = "com_github_afex_hystrix_go",
        importpath = "github.com/afex/hystrix-go",
        sum = "h1:rFw4nCn9iMW+Vajsk51NtYIcwSTkXr+JGrMd36kTDJw=",
        version = "v0.0.0-20180502004556-fa1af6a1f4f5",
    )
    go_repository(
        name = "com_github_alecthomas_template",
        importpath = "github.com/alecthomas/template",
        sum = "h1:JYp7IbQjafoB+tBA3gMyHYHrpOtNuDiK/uB5uXxq5wM=",
        version = "v0.0.0-20190718012654-fb15b899a751",
    )
    go_repository(
        name = "com_github_alecthomas_units",
        importpath = "github.com/alecthomas/units",
        sum = "h1:Hs82Z41s6SdL1CELW+XaDYmOH4hkBN4/N9og/AsOv7E=",
        version = "v0.0.0-20190717042225-c3de453c63f4",
    )
    go_repository(
        name = "com_github_anmitsu_go_shlex",
        importpath = "github.com/anmitsu/go-shlex",
        sum = "h1:kFOfPq6dUM1hTo4JG6LR5AXSUEsOjtdm0kw0FtQtMJA=",
        version = "v0.0.0-20161002113705-648efa622239",
    )
    go_repository(
        name = "com_github_antlr_antlr4",
        importpath = "github.com/antlr/antlr4",
        sum = "h1:yxMh4HIdsSh2EqxUESWvzszYMNzOugRyYCeohfwNULM=",
        version = "v0.0.0-20181218183524-be58ebffde8e",
    )
    go_repository(
        name = "com_github_apache_thrift",
        importpath = "github.com/apache/thrift",
        sum = "h1:5hryIiq9gtn+MiLVn0wP37kb/uTeRZgN08WoCsAhIhI=",
        version = "v0.13.0",
    )
    go_repository(
        name = "com_github_armon_circbuf",
        importpath = "github.com/armon/circbuf",
        sum = "h1:QEF07wC0T1rKkctt1RINW/+RMTVmiwxETico2l3gxJA=",
        version = "v0.0.0-20150827004946-bbbad097214e",
    )
    go_repository(
        name = "com_github_armon_go_metrics",
        importpath = "github.com/armon/go-metrics",
        sum = "h1:8GUt8eRujhVEGZFFEjBj46YV4rDjvGrNxb0KMWYkL2I=",
        version = "v0.0.0-20180917152333-f0300d1749da",
    )
    go_repository(
        name = "com_github_armon_go_radix",
        importpath = "github.com/armon/go-radix",
        sum = "h1:BUAU3CGlLvorLI26FmByPp2eC2qla6E1Tw+scpcg/to=",
        version = "v0.0.0-20180808171621-7fddfc383310",
    )
    go_repository(
        name = "com_github_aryann_difflib",
        importpath = "github.com/aryann/difflib",
        sum = "h1:pv34s756C4pEXnjgPfGYgdhg/ZdajGhyOvzx8k+23nw=",
        version = "v0.0.0-20170710044230-e206f873d14a",
    )
    go_repository(
        name = "com_github_aws_aws_lambda_go",
        importpath = "github.com/aws/aws-lambda-go",
        sum = "h1:SuCy7H3NLyp+1Mrfp+m80jcbi9KYWAs9/BXwppwRDzY=",
        version = "v1.13.3",
    )
    go_repository(
        name = "com_github_aws_aws_sdk_go",
        importpath = "github.com/aws/aws-sdk-go",
        sum = "h1:0xphMHGMLBrPMfxR2AmVjZKcMEESEgWF8Kru94BNByk=",
        version = "v1.27.0",
    )
    go_repository(
        name = "com_github_aws_aws_sdk_go_v2",
        importpath = "github.com/aws/aws-sdk-go-v2",
        sum = "h1:qZ+woO4SamnH/eEbjM2IDLhRNwIwND/RQyVlBLp3Jqg=",
        version = "v0.18.0",
    )
    go_repository(
        name = "com_github_bazelbuild_rules_go",
        importpath = "github.com/bazelbuild/rules_go",
        sum = "h1:KViqR7qKXwz+LrNdIauCDU21kneCk+4DnYjpvlJwH50=",
        version = "v0.27.0",
    )
    go_repository(
        name = "com_github_beorn7_perks",
        importpath = "github.com/beorn7/perks",
        sum = "h1:VlbKKnNfV8bJzeqoa4cOKqO6bYr3WgKZxO8Z16+hsOM=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_bgentry_speakeasy",
        importpath = "github.com/bgentry/speakeasy",
        sum = "h1:ByYyxL9InA1OWqxJqqp2A5pYHUrCiAL6K3J+LKSsQkY=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_bketelsen_crypt",
        importpath = "github.com/bketelsen/crypt",
        sum = "h1:+0HFd5KSZ/mm3JmhmrDukiId5iR6w4+BdFtfSy4yWIc=",
        version = "v0.0.3-0.20200106085610-5cbc8cc4026c",
    )
    go_repository(
        name = "com_github_bradfitz_go_smtpd",
        importpath = "github.com/bradfitz/go-smtpd",
        sum = "h1:ckJgFhFWywOx+YLEMIJsTb+NV6NexWICk5+AMSuz3ss=",
        version = "v0.0.0-20170404230938-deb6d6237625",
    )
    go_repository(
        name = "com_github_buger_jsonparser",
        importpath = "github.com/buger/jsonparser",
        sum = "h1:D21IyuvjDCshj1/qq+pCNd3VZOAEI9jy6Bi131YlXgI=",
        version = "v0.0.0-20181115193947-bf1c66bbce23",
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
        name = "com_github_burntsushi_xgb",
        importpath = "github.com/BurntSushi/xgb",
        sum = "h1:1BDTz0u9nC3//pOCMdNH+CiXJVYJh5UQNCOBG7jbELc=",
        version = "v0.0.0-20160522181843-27f122750802",
    )
    go_repository(
        name = "com_github_casbin_casbin_v2",
        importpath = "github.com/casbin/casbin/v2",
        sum = "h1:bTwon/ECRx9dwBy2ewRVr5OiqjeXSGiTUY74sDPQi/g=",
        version = "v2.1.2",
    )
    go_repository(
        name = "com_github_cenkalti_backoff",
        importpath = "github.com/cenkalti/backoff",
        sum = "h1:tNowT99t7UNflLxfYYSlKYsBpXdEet03Pg2g16Swow4=",
        version = "v2.2.1+incompatible",
    )
    go_repository(
        name = "com_github_census_instrumentation_opencensus_proto",
        importpath = "github.com/census-instrumentation/opencensus-proto",
        sum = "h1:glEXhBS5PSLLv4IXzLA5yPRVX4bilULVyxxbrfOtDAk=",
        version = "v0.2.1",
    )
    go_repository(
        name = "com_github_cespare_xxhash",
        importpath = "github.com/cespare/xxhash",
        sum = "h1:a6HrQnmkObjyL+Gs60czilIUGqrzKutQD6XZog3p+ko=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_cespare_xxhash_v2",
        importpath = "github.com/cespare/xxhash/v2",
        sum = "h1:6MnRN8NT7+YBpUIWxHtefFZOKTAPgGjpQSxqLNn0+qY=",
        version = "v2.1.1",
    )
    go_repository(
        name = "com_github_cheekybits_genny",
        importpath = "github.com/cheekybits/genny",
        sum = "h1:uGGa4nei+j20rOSeDeP5Of12XVm7TGUd4dJA9RDitfE=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_clbanning_x2j",
        importpath = "github.com/clbanning/x2j",
        sum = "h1:EdRZT3IeKQmfCSrgo8SZ8V3MEnskuJP0wCYNpe+aiXo=",
        version = "v0.0.0-20191024224557-825249438eec",
    )
    go_repository(
        name = "com_github_client9_misspell",
        importpath = "github.com/client9/misspell",
        sum = "h1:ta993UF76GwbvJcIo3Y68y/M3WxlpEHPWIGDkJYwzJI=",
        version = "v0.3.4",
    )
    go_repository(
        name = "com_github_cncf_udpa_go",
        importpath = "github.com/cncf/udpa/go",
        sum = "h1:WBZRG4aNOuI15bLRrCgN8fCq8E5Xuty6jGbmSNEvSsU=",
        version = "v0.0.0-20191209042840-269d4d468f6f",
    )
    go_repository(
        name = "com_github_cockroachdb_datadriven",
        importpath = "github.com/cockroachdb/datadriven",
        sum = "h1:OaNxuTZr7kxeODyLWsRMC+OD03aFUH+mW6r2d+MWa5Y=",
        version = "v0.0.0-20190809214429-80d97fb3cbaa",
    )
    go_repository(
        name = "com_github_codahale_hdrhistogram",
        importpath = "github.com/codahale/hdrhistogram",
        sum = "h1:qMd81Ts1T2OTKmB4acZcyKaMtRnY5Y44NuXGX2GFJ1w=",
        version = "v0.0.0-20161010025455-3a0bb77429bd",
    )
    go_repository(
        name = "com_github_coreos_bbolt",
        importpath = "github.com/coreos/bbolt",
        sum = "h1:wZwiHHUieZCquLkDL0B8UhzreNWsPHooDAG3q34zk0s=",
        version = "v1.3.2",
    )
    go_repository(
        name = "com_github_coreos_etcd",
        importpath = "github.com/coreos/etcd",
        sum = "h1:8F3hqu9fGYLBifCmRCJsicFqDx/D68Rt3q1JMazcgBQ=",
        version = "v3.3.13+incompatible",
    )
    go_repository(
        name = "com_github_coreos_go_semver",
        importpath = "github.com/coreos/go-semver",
        sum = "h1:wkHLiw0WNATZnSG7epLsujiMCgPAc9xhjJ4tgnAxmfM=",
        version = "v0.3.0",
    )
    go_repository(
        name = "com_github_coreos_go_systemd",
        importpath = "github.com/coreos/go-systemd",
        sum = "h1:Wf6HqHfScWJN9/ZjdUKyjop4mf3Qdd+1TvvltAvM3m8=",
        version = "v0.0.0-20190321100706-95778dfbb74e",
    )
    go_repository(
        name = "com_github_coreos_pkg",
        importpath = "github.com/coreos/pkg",
        sum = "h1:lBNOc5arjvs8E5mO2tbpBpLoyyu8B6e44T7hJy6potg=",
        version = "v0.0.0-20180928190104-399ea9e2e55f",
    )
    go_repository(
        name = "com_github_cpuguy83_go_md2man_v2",
        importpath = "github.com/cpuguy83/go-md2man/v2",
        sum = "h1:EoUDS0afbrsXAZ9YQ9jdu/mZ2sXgT1/2yyNng4PGlyM=",
        version = "v2.0.0",
    )
    go_repository(
        name = "com_github_creack_pty",
        importpath = "github.com/creack/pty",
        sum = "h1:uDmaGzcdjhF4i/plgjmEsriH11Y0o7RKapEf/LDaM3w=",
        version = "v1.1.9",
    )
    go_repository(
        name = "com_github_cyberdelia_templates",
        importpath = "github.com/cyberdelia/templates",
        sum = "h1:/ovYnF02fwL0kvspmy9AuyKg1JhdTRUgPw4nUxd9oZM=",
        version = "v0.0.0-20141128023046-ca7fffd4298c",
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
        name = "com_github_decred_dcrd_chaincfg_chainhash",
        importpath = "github.com/decred/dcrd/chaincfg/chainhash",
        sum = "h1:rt5Vlq/jM3ZawwiacWjPa+smINyLRN07EO0cNBV6DGU=",
        version = "v1.0.2",
    )
    go_repository(
        name = "com_github_decred_dcrd_crypto_blake256",
        importpath = "github.com/decred/dcrd/crypto/blake256",
        sum = "h1:/8DMNYp9SGi5f0w7uCm6d6M4OU2rGFK09Y2A4Xv7EE0=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_decred_dcrd_dcrec_secp256k1_v3",
        importpath = "github.com/decred/dcrd/dcrec/secp256k1/v3",
        sum = "h1:sgNeV1VRMDzs6rzyPpxyM0jp317hnwiq58Filgag2xw=",
        version = "v3.0.0",
    )
    go_repository(
        name = "com_github_deepmap_oapi_codegen",
        importpath = "github.com/deepmap/oapi-codegen",
        sum = "h1:2BvsmRb6pogGNtr8Ann+esAbSKFXx2CZN18VpAMecnw=",
        version = "v1.6.1",
    )
    go_repository(
        name = "com_github_dgrijalva_jwt_go",
        importpath = "github.com/dgrijalva/jwt-go",
        sum = "h1:7qlOGliEKZXTDg6OTjfoBKDXWrumCAMpl/TFQ4/5kLM=",
        version = "v3.2.0+incompatible",
    )
    go_repository(
        name = "com_github_dgryski_go_sip13",
        importpath = "github.com/dgryski/go-sip13",
        sum = "h1:RMLoZVzv4GliuWafOuPuQDKSm1SJph7uCRnnS61JAn4=",
        version = "v0.0.0-20181026042036-e10d5fee7954",
    )
    go_repository(
        name = "com_github_dustin_go_humanize",
        importpath = "github.com/dustin/go-humanize",
        sum = "h1:VSnTsYCnlFHaM2/igO1h6X3HA71jcobQuxemgkq4zYo=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_eapache_go_resiliency",
        importpath = "github.com/eapache/go-resiliency",
        sum = "h1:1NtRmCAqadE2FN4ZcN6g90TP3uk8cg9rn9eNK2197aU=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_eapache_go_xerial_snappy",
        importpath = "github.com/eapache/go-xerial-snappy",
        sum = "h1:YEetp8/yCZMuEPMUDHG0CW/brkkEp8mzqk2+ODEitlw=",
        version = "v0.0.0-20180814174437-776d5712da21",
    )
    go_repository(
        name = "com_github_eapache_queue",
        importpath = "github.com/eapache/queue",
        sum = "h1:YOEu7KNc61ntiQlcEeUIoDTJ2o8mQznoNvUhiigpIqc=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_edsrzf_mmap_go",
        importpath = "github.com/edsrzf/mmap-go",
        sum = "h1:CEBF7HpRnUCSJgGUb5h1Gm7e3VkmVDrR8lvWVLtrOFw=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_envoyproxy_go_control_plane",
        importpath = "github.com/envoyproxy/go-control-plane",
        sum = "h1:rEvIZUSZ3fx39WIi3JkQqQBitGwpELBIYWeBVh6wn+E=",
        version = "v0.9.4",
    )
    go_repository(
        name = "com_github_envoyproxy_protoc_gen_validate",
        importpath = "github.com/envoyproxy/protoc-gen-validate",
        sum = "h1:EQciDnbrYxy13PgWoY8AqoxGiPrpgBZ1R8UNe3ddc+A=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_fatih_color",
        importpath = "github.com/fatih/color",
        sum = "h1:8xPHl4/q1VyqGIPif1F+1V3Y3lSmrq01EabUW3CoW5s=",
        version = "v1.9.0",
    )
    go_repository(
        name = "com_github_flynn_go_shlex",
        importpath = "github.com/flynn/go-shlex",
        sum = "h1:BHsljHzVlRcyQhjrss6TZTdY2VfCqZPbv5k3iBFa2ZQ=",
        version = "v0.0.0-20150515145356-3f9db97f8568",
    )
    go_repository(
        name = "com_github_francoispqt_gojay",
        importpath = "github.com/francoispqt/gojay",
        sum = "h1:d2m3sFjloqoIUQU3TsHBgj6qg/BVGlTBeHDUmyJnXKk=",
        version = "v1.2.13",
    )
    go_repository(
        name = "com_github_franela_goblin",
        importpath = "github.com/franela/goblin",
        sum = "h1:gb2Z18BhTPJPpLQWj4T+rfKHYCHxRHCtRxhKKjRidVw=",
        version = "v0.0.0-20200105215937-c9ffbefa60db",
    )
    go_repository(
        name = "com_github_franela_goreq",
        importpath = "github.com/franela/goreq",
        sum = "h1:a9ENSRDFBUPkJ5lCgVZh26+ZbGyoVJG7yb5SSzF5H54=",
        version = "v0.0.0-20171204163338-bcd34c9993f8",
    )
    go_repository(
        name = "com_github_fsnotify_fsnotify",
        importpath = "github.com/fsnotify/fsnotify",
        sum = "h1:hsms1Qyu0jgnwNXIxa+/V/PDsU6CfLf6CNO8H7IWoS4=",
        version = "v1.4.9",
    )
    go_repository(
        name = "com_github_getkin_kin_openapi",
        importpath = "github.com/getkin/kin-openapi",
        sum = "h1:7WzP+MZRRe7YQz2Kc74Ley3dukJmXDvifVbElGmQfoA=",
        version = "v0.53.0",
    )
    go_repository(
        name = "com_github_ghodss_yaml",
        importpath = "github.com/ghodss/yaml",
        sum = "h1:wQHKEahhL6wmXdzwWG11gIVCkOv05bNOh+Rxn0yngAk=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_gliderlabs_ssh",
        importpath = "github.com/gliderlabs/ssh",
        sum = "h1:j3L6gSLQalDETeEg/Jg0mGY0/y/N6zI2xX1978P0Uqw=",
        version = "v0.1.1",
    )
    go_repository(
        name = "com_github_go_chi_chi_v5",
        importpath = "github.com/go-chi/chi/v5",
        sum = "h1:4xKeALZdMEsuI5s05PU2Bm89Uc5iM04qFubUCl5LfAQ=",
        version = "v5.0.2",
    )
    go_repository(
        name = "com_github_go_chi_cors",
        importpath = "github.com/go-chi/cors",
        sum = "h1:eHuqxsIw89iXcWnWUN8R72JMibABJTN/4IOYI5WERvw=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_go_errors_errors",
        importpath = "github.com/go-errors/errors",
        sum = "h1:LUHzmkK3GUKUrL/1gfBUxAHzcev3apQlezX/+O7ma6w=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_go_gl_glfw",
        importpath = "github.com/go-gl/glfw",
        sum = "h1:QbL/5oDUmRBzO9/Z7Seo6zf912W/a6Sr4Eu0G/3Jho0=",
        version = "v0.0.0-20190409004039-e6da0acd62b1",
    )
    go_repository(
        name = "com_github_go_kit_kit",
        importpath = "github.com/go-kit/kit",
        sum = "h1:dXFJfIHVvUcpSgDOV+Ne6t7jXri8Tfv2uOLHUZ2XNuo=",
        version = "v0.10.0",
    )
    go_repository(
        name = "com_github_go_logfmt_logfmt",
        importpath = "github.com/go-logfmt/logfmt",
        sum = "h1:TrB8swr/68K7m9CcGut2g3UOihhbcbiMAYiuTXdEih4=",
        version = "v0.5.0",
    )
    go_repository(
        name = "com_github_go_openapi_jsonpointer",
        importpath = "github.com/go-openapi/jsonpointer",
        sum = "h1:gZr+CIYByUqjcgeLXnQu2gHYQC9o73G2XUeOFYEICuY=",
        version = "v0.19.5",
    )
    go_repository(
        name = "com_github_go_openapi_swag",
        importpath = "github.com/go-openapi/swag",
        sum = "h1:gm3vOOXfiuw5i9p5N9xJvfjvuofpyvLA9Wr6QfK5Fng=",
        version = "v0.19.14",
    )
    go_repository(
        name = "com_github_go_sql_driver_mysql",
        importpath = "github.com/go-sql-driver/mysql",
        sum = "h1:7LxgVwFb2hIQtMm87NdgAVfXjnt4OePseqT1tKx+opk=",
        version = "v1.4.0",
    )
    go_repository(
        name = "com_github_go_stack_stack",
        importpath = "github.com/go-stack/stack",
        sum = "h1:5SgMzNM5HxrEjV0ww2lTmX6E2Izsfxas4+YHWRs3Lsk=",
        version = "v1.8.0",
    )
    go_repository(
        name = "com_github_goccy_go_json",
        importpath = "github.com/goccy/go-json",
        sum = "h1:xGUjaNfhpqhKAV2LoyNXihFLZ8ABSST8B+W+duHqkPI=",
        version = "v0.4.7",
    )
    go_repository(
        name = "com_github_gogo_googleapis",
        importpath = "github.com/gogo/googleapis",
        sum = "h1:kFkMAZBNAn4j7K0GiZr8cRYzejq68VbheufiV3YuyFI=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_gogo_protobuf",
        importpath = "github.com/gogo/protobuf",
        sum = "h1:/s5zKNz0uPFCZ5hddgPdo2TK2TVrUNMn0OOX8/aZMTE=",
        version = "v1.2.1",
    )
    go_repository(
        name = "com_github_golang_glog",
        importpath = "github.com/golang/glog",
        sum = "h1:VKtxabqXZkF25pY9ekfRL6a582T4P37/31XEstQ5p58=",
        version = "v0.0.0-20160126235308-23def4e6c14b",
    )
    go_repository(
        name = "com_github_golang_groupcache",
        importpath = "github.com/golang/groupcache",
        sum = "h1:uHTyIjqVhYRhLbJ8nIiOJHkEZZ+5YoOsAbD3sk82NiE=",
        version = "v0.0.0-20191027212112-611e8accdfc9",
    )
    go_repository(
        name = "com_github_golang_lint",
        importpath = "github.com/golang/lint",
        sum = "h1:2hRPrmiwPrp3fQX967rNJIhQPtiGXdlQWAxKbKw3VHA=",
        version = "v0.0.0-20180702182130-06c8688daad7",
    )
    go_repository(
        name = "com_github_golang_mock",
        importpath = "github.com/golang/mock",
        sum = "h1:l75CXGRSwbaYNpl/Z2X1XIIAMSCquvXgpVZDhwEIJsc=",
        version = "v1.4.4",
    )
    go_repository(
        name = "com_github_golang_protobuf",
        importpath = "github.com/golang/protobuf",
        sum = "h1:+Z5KGCizgyZCbGh1KZqA0fcLLkwbsjIzS4aV2v7wJX0=",
        version = "v1.4.2",
    )
    go_repository(
        name = "com_github_golang_snappy",
        importpath = "github.com/golang/snappy",
        sum = "h1:woRePGFeVFfLKN/pOkfl+p/TAqKOfFu+7KPlMVpok/w=",
        version = "v0.0.0-20180518054509-2e65f85255db",
    )
    go_repository(
        name = "com_github_golangci_lint_1",
        importpath = "github.com/golangci/lint-1",
        sum = "h1:utua3L2IbQJmauC5IXdEA547bcoU5dozgQAfc8Onsg4=",
        version = "v0.0.0-20181222135242-d2cdd8c08219",
    )
    go_repository(
        name = "com_github_google_btree",
        importpath = "github.com/google/btree",
        sum = "h1:0udJVsspx3VBr5FwtLhQQtuAsVc79tTq0ocGIPAU6qo=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_google_go_cmp",
        importpath = "github.com/google/go-cmp",
        sum = "h1:xsAVV57WRhGj6kEIi8ReJzQlHHqcBYCElAvkovg3B/4=",
        version = "v0.4.0",
    )
    go_repository(
        name = "com_github_google_go_github",
        importpath = "github.com/google/go-github",
        sum = "h1:N0LgJ1j65A7kfXrZnUDaYCs/Sf4rEjNlfyDHW9dolSY=",
        version = "v17.0.0+incompatible",
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
        name = "com_github_google_martian",
        importpath = "github.com/google/martian",
        sum = "h1:/CP5g8u/VJHijgedC/Legn3BAbAaWPgecwXBIDzw5no=",
        version = "v2.1.0+incompatible",
    )
    go_repository(
        name = "com_github_google_pprof",
        importpath = "github.com/google/pprof",
        sum = "h1:Jnx61latede7zDD3DiiP4gmNz33uK0U5HDUaF0a/HVQ=",
        version = "v0.0.0-20190515194954-54271f7e092f",
    )
    go_repository(
        name = "com_github_google_renameio",
        importpath = "github.com/google/renameio",
        sum = "h1:GOZbcHa3HfsPKPlmyPyN2KEohoMXOhdMbHrvbpl2QaA=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_google_uuid",
        importpath = "github.com/google/uuid",
        sum = "h1:b4Gk+7WdP/d3HZH8EJsZpvV7EtDOgaZLtnaNGIu1adA=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_googleapis_gax_go",
        importpath = "github.com/googleapis/gax-go",
        sum = "h1:j0GKcs05QVmm7yesiZq2+9cxHkNK9YM6zKx4D2qucQU=",
        version = "v2.0.0+incompatible",
    )
    go_repository(
        name = "com_github_googleapis_gax_go_v2",
        importpath = "github.com/googleapis/gax-go/v2",
        sum = "h1:sjZBwGj9Jlw33ImPtvFviGYvseOtDM7hkSKB7+Tv3SM=",
        version = "v2.0.5",
    )
    go_repository(
        name = "com_github_gopherjs_gopherjs",
        importpath = "github.com/gopherjs/gopherjs",
        sum = "h1:EGx4pi6eqNxGaHF6qqu48+N2wcFQ5qg5FXgOdqsJ5d8=",
        version = "v0.0.0-20181017120253-0766667cb4d1",
    )
    go_repository(
        name = "com_github_gorilla_context",
        importpath = "github.com/gorilla/context",
        sum = "h1:AWwleXJkX/nhcU9bZSnZoi3h/qGYqQAGhq6zZe/aQW8=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_gorilla_mux",
        importpath = "github.com/gorilla/mux",
        sum = "h1:i40aqfkR1h2SlN9hojwV5ZA91wcXFOvkdNIeFDP5koI=",
        version = "v1.8.0",
    )
    go_repository(
        name = "com_github_gorilla_websocket",
        importpath = "github.com/gorilla/websocket",
        sum = "h1:+/TMaTYc4QFitKJxsQ7Yye35DkWvkdLcvGKqM+x0Ufc=",
        version = "v1.4.2",
    )
    go_repository(
        name = "com_github_gregjones_httpcache",
        importpath = "github.com/gregjones/httpcache",
        sum = "h1:pdN6V1QBWetyv/0+wjACpqVH+eVULgEjkurDLq3goeM=",
        version = "v0.0.0-20180305231024-9cad4c3443a7",
    )
    go_repository(
        name = "com_github_grpc_ecosystem_go_grpc_middleware",
        importpath = "github.com/grpc-ecosystem/go-grpc-middleware",
        sum = "h1:z53tR0945TRRQO/fLEVPI6SMv7ZflF0TEaTAoU7tOzg=",
        version = "v1.0.1-0.20190118093823-f849b5445de4",
    )
    go_repository(
        name = "com_github_grpc_ecosystem_go_grpc_prometheus",
        importpath = "github.com/grpc-ecosystem/go-grpc-prometheus",
        sum = "h1:Ovs26xHkKqVztRpIrF/92BcuyuQ/YW4NSIpoGtfXNho=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_grpc_ecosystem_grpc_gateway",
        importpath = "github.com/grpc-ecosystem/grpc-gateway",
        sum = "h1:UImYN5qQ8tuGpGE16ZmjvcTtTw24zw1QAp/SlnNrZhI=",
        version = "v1.9.5",
    )
    go_repository(
        name = "com_github_grpc_ecosystem_grpc_opentracing",
        importpath = "github.com/grpc-ecosystem/grpc-opentracing",
        sum = "h1:MJG/KsmcqMwFAkh8mTnAwhyKoB+sTAnY4CACC110tbU=",
        version = "v0.0.0-20180507213350-8e809c8a8645",
    )
    go_repository(
        name = "com_github_hashicorp_consul_api",
        importpath = "github.com/hashicorp/consul/api",
        sum = "h1:HXNYlRkkM/t+Y/Yhxtwcy02dlYwIaoxzvxPnS+cqy78=",
        version = "v1.3.0",
    )
    go_repository(
        name = "com_github_hashicorp_consul_sdk",
        importpath = "github.com/hashicorp/consul/sdk",
        sum = "h1:UOxjlb4xVNF93jak1mzzoBatyFju9nrkxpVwIp/QqxQ=",
        version = "v0.3.0",
    )
    go_repository(
        name = "com_github_hashicorp_errwrap",
        importpath = "github.com/hashicorp/errwrap",
        sum = "h1:hLrqtEDnRye3+sgx6z4qVLNuviH3MR5aQ0ykNJa/UYA=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hashicorp_go_cleanhttp",
        importpath = "github.com/hashicorp/go-cleanhttp",
        sum = "h1:dH3aiDG9Jvb5r5+bYHsikaOUIpcM0xvgMXVoDkXMzJM=",
        version = "v0.5.1",
    )
    go_repository(
        name = "com_github_hashicorp_go_immutable_radix",
        importpath = "github.com/hashicorp/go-immutable-radix",
        sum = "h1:AKDB1HM5PWEA7i4nhcpwOrO2byshxBjXVn/J/3+z5/0=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hashicorp_go_msgpack",
        importpath = "github.com/hashicorp/go-msgpack",
        sum = "h1:zKjpN5BK/P5lMYrLmBHdBULWbJ0XpYR+7NGzqkZzoD4=",
        version = "v0.5.3",
    )
    go_repository(
        name = "com_github_hashicorp_go_multierror",
        importpath = "github.com/hashicorp/go-multierror",
        sum = "h1:iVjPR7a6H0tWELX5NxNe7bYopibicUzc7uPribsnS6o=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hashicorp_go_net",
        importpath = "github.com/hashicorp/go.net",
        sum = "h1:sNCoNyDEvN1xa+X0baata4RdcpKwcMS6DH+xwfqPgjw=",
        version = "v0.0.1",
    )
    go_repository(
        name = "com_github_hashicorp_go_rootcerts",
        importpath = "github.com/hashicorp/go-rootcerts",
        sum = "h1:Rqb66Oo1X/eSV1x66xbDccZjhJigjg0+e82kpwzSwCI=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hashicorp_go_sockaddr",
        importpath = "github.com/hashicorp/go-sockaddr",
        sum = "h1:GeH6tui99pF4NJgfnhp+L6+FfobzVW3Ah46sLo0ICXs=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hashicorp_go_syslog",
        importpath = "github.com/hashicorp/go-syslog",
        sum = "h1:KaodqZuhUoZereWVIYmpUgZysurB1kBLX2j0MwMrUAE=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hashicorp_go_uuid",
        importpath = "github.com/hashicorp/go-uuid",
        sum = "h1:fv1ep09latC32wFoVwnqcnKJGnMSdBanPczbHAYm1BE=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_hashicorp_go_version",
        importpath = "github.com/hashicorp/go-version",
        sum = "h1:3vNe/fWF5CBgRIguda1meWhsZHy3m8gCJ5wx+dIzX/E=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_hashicorp_golang_lru",
        importpath = "github.com/hashicorp/golang-lru",
        sum = "h1:0hERBMJE1eitiLkihrMvRVBYAkpHzc/J3QdDN+dAcgU=",
        version = "v0.5.1",
    )
    go_repository(
        name = "com_github_hashicorp_hcl",
        importpath = "github.com/hashicorp/hcl",
        sum = "h1:0Anlzjpi4vEasTeNFn2mLJgTSwt0+6sfsiTG8qcWGx4=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hashicorp_logutils",
        importpath = "github.com/hashicorp/logutils",
        sum = "h1:dLEQVugN8vlakKOUE3ihGLTZJRB4j+M2cdTm/ORI65Y=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hashicorp_mdns",
        importpath = "github.com/hashicorp/mdns",
        sum = "h1:WhIgCr5a7AaVH6jPUwjtRuuE7/RDufnUvzIr48smyxs=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hashicorp_memberlist",
        importpath = "github.com/hashicorp/memberlist",
        sum = "h1:EmmoJme1matNzb+hMpDuR/0sbJSUisxyqBGG676r31M=",
        version = "v0.1.3",
    )
    go_repository(
        name = "com_github_hashicorp_serf",
        importpath = "github.com/hashicorp/serf",
        sum = "h1:YZ7UKsJv+hKjqGVUUbtE3HNj79Eln2oQ75tniF6iPt0=",
        version = "v0.8.2",
    )
    go_repository(
        name = "com_github_hpcloud_tail",
        importpath = "github.com/hpcloud/tail",
        sum = "h1:nfCOvKYfkgYP8hkirhJocXT2+zOD8yUNjXaWfTlyFKI=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_hudl_fargo",
        importpath = "github.com/hudl/fargo",
        sum = "h1:0U6+BtN6LhaYuTnIJq4Wyq5cpn6O2kWrxAtcqBmYY6w=",
        version = "v1.3.0",
    )
    go_repository(
        name = "com_github_iancoleman_strcase",
        importpath = "github.com/iancoleman/strcase",
        sum = "h1:ECW73yc9MY7935nNYXUkK7Dz17YuSUI9yqRqYS8aBww=",
        version = "v0.0.0-20190422225806-e506e3ef7365",
    )
    go_repository(
        name = "com_github_inconshreveable_mousetrap",
        importpath = "github.com/inconshreveable/mousetrap",
        sum = "h1:Z8tu5sraLXCXIcARxBp/8cbvlwVa7Z1NHg9XEKhtSvM=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_influxdata_influxdb1_client",
        importpath = "github.com/influxdata/influxdb1-client",
        sum = "h1:/WZQPMZNsjZ7IlCpsLGdQBINg5bxKQ1K1sh6awxLtkA=",
        version = "v0.0.0-20191209144304-8bf82d3c094d",
    )
    go_repository(
        name = "com_github_jellevandenhooff_dkim",
        importpath = "github.com/jellevandenhooff/dkim",
        sum = "h1:ujPKutqRlJtcfWk6toYVYagwra7HQHbXOaS171b4Tg8=",
        version = "v0.0.0-20150330215556-f50fe3d243e1",
    )
    go_repository(
        name = "com_github_jmespath_go_jmespath",
        importpath = "github.com/jmespath/go-jmespath",
        sum = "h1:pmfjZENx5imkbgOkpRUYLnmbU7UEFbjtDA2hxJ1ichM=",
        version = "v0.0.0-20180206201540-c2b33e8439af",
    )
    go_repository(
        name = "com_github_jonboulle_clockwork",
        importpath = "github.com/jonboulle/clockwork",
        sum = "h1:VKV+ZcuP6l3yW9doeqz6ziZGgcynBVQO+obU0+0hcPo=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_josharian_intern",
        importpath = "github.com/josharian/intern",
        sum = "h1:vlS4z54oSdjm0bgjRigI+G1HpF+tI+9rE5LLzOg8HmY=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_json_iterator_go",
        importpath = "github.com/json-iterator/go",
        sum = "h1:9yzud/Ht36ygwatGx56VwCZtlI/2AD15T1X2sjSuGns=",
        version = "v1.1.9",
    )
    go_repository(
        name = "com_github_jstemmer_go_junit_report",
        importpath = "github.com/jstemmer/go-junit-report",
        sum = "h1:rBMNdlhTLzJjJSDIjNEXX1Pz3Hmwmz91v+zycvx9PJc=",
        version = "v0.0.0-20190106144839-af01ea7f8024",
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
        name = "com_github_kisielk_errcheck",
        importpath = "github.com/kisielk/errcheck",
        sum = "h1:ZqfnKyx9KGpRcW04j5nnPDgRgoXUeLh2YFBeFzphcA0=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_kisielk_gotool",
        importpath = "github.com/kisielk/gotool",
        sum = "h1:AV2c/EiW3KqPNT9ZKl07ehoAGi4C5/01Cfbblndcapg=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_knetic_govaluate",
        importpath = "github.com/Knetic/govaluate",
        sum = "h1:1G1pk05UrOh0NlF1oeaaix1x8XzrfjIDK47TY0Zehcw=",
        version = "v3.0.1-0.20171022003610-9aa49832a739+incompatible",
    )
    go_repository(
        name = "com_github_konsorten_go_windows_terminal_sequences",
        importpath = "github.com/konsorten/go-windows-terminal-sequences",
        sum = "h1:mweAR1A6xJ3oS2pRaGiHgQ4OO8tzTaLawm8vnODuwDk=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_kr_logfmt",
        importpath = "github.com/kr/logfmt",
        sum = "h1:T+h1c/A9Gawja4Y9mFVWj2vyii2bbUNDw3kt9VxK2EY=",
        version = "v0.0.0-20140226030751-b84e30acd515",
    )
    go_repository(
        name = "com_github_kr_pretty",
        importpath = "github.com/kr/pretty",
        sum = "h1:L/CwN0zerZDmRFUapSPitk6f+Q3+0za1rQkzVuMiMFI=",
        version = "v0.1.0",
    )
    go_repository(
        name = "com_github_kr_pty",
        importpath = "github.com/kr/pty",
        sum = "h1:/Um6a/ZmD5tF7peoOJ5oN5KMQ0DrGVQSXLNwyckutPk=",
        version = "v1.1.3",
    )
    go_repository(
        name = "com_github_kr_text",
        importpath = "github.com/kr/text",
        sum = "h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=",
        version = "v0.2.0",
    )
    go_repository(
        name = "com_github_kylelemons_godebug",
        importpath = "github.com/kylelemons/godebug",
        sum = "h1:RPNrshWIDI6G2gRW9EHilWtl7Z6Sb1BR0xunSBf0SNc=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_labstack_echo_v4",
        importpath = "github.com/labstack/echo/v4",
        sum = "h1:LF5Iq7t/jrtUuSutNuiEWtB5eiHfZ5gSe2pcu5exjQw=",
        version = "v4.2.1",
    )
    go_repository(
        name = "com_github_labstack_gommon",
        importpath = "github.com/labstack/gommon",
        sum = "h1:JEeO0bvc78PKdyHxloTKiF8BD5iGrH8T6MSeGvSgob0=",
        version = "v0.3.0",
    )
    go_repository(
        name = "com_github_lestrrat_go_backoff_v2",
        importpath = "github.com/lestrrat-go/backoff/v2",
        sum = "h1:i2SeK33aOFJlUNJZzf2IpXRBvqBBnaGXfY5Xaop/GsE=",
        version = "v2.0.7",
    )
    go_repository(
        name = "com_github_lestrrat_go_codegen",
        importpath = "github.com/lestrrat-go/codegen",
        sum = "h1:gnWFHKvL64TTSFRghShUybm9UvBxFFXvnniE06JTO3k=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_lestrrat_go_httpcc",
        importpath = "github.com/lestrrat-go/httpcc",
        sum = "h1:FszVC6cKfDvBKcJv646+lkh4GydQg2Z29scgUfkOpYc=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_lestrrat_go_iter",
        importpath = "github.com/lestrrat-go/iter",
        sum = "h1:QD+hHQPDSHC4rCJkZYY/yXChYr/vjfBopKekTc+7l4Q=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_lestrrat_go_jwx",
        importpath = "github.com/lestrrat-go/jwx",
        sum = "h1:TZ0Vly07R/duLIRS11CennIovzBvzF46ofWGj1vB26A=",
        version = "v1.1.5",
    )
    go_repository(
        name = "com_github_lestrrat_go_option",
        importpath = "github.com/lestrrat-go/option",
        sum = "h1:WqAWL8kh8VcSoD6xjSH34/1m8yxluXQbDeKNfvFeEO4=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_lestrrat_go_pdebug_v3",
        importpath = "github.com/lestrrat-go/pdebug/v3",
        sum = "h1:3G5sX/aw/TbMTtVc9U7IHBWRZtMvwvBziF1e4HoQtv8=",
        version = "v3.0.1",
    )
    go_repository(
        name = "com_github_lightstep_lightstep_tracer_common_golang_gogo",
        importpath = "github.com/lightstep/lightstep-tracer-common/golang/gogo",
        sum = "h1:143Bb8f8DuGWck/xpNUOckBVYfFbBTnLevfRZ1aVVqo=",
        version = "v0.0.0-20190605223551-bc2310a04743",
    )
    go_repository(
        name = "com_github_lightstep_lightstep_tracer_go",
        importpath = "github.com/lightstep/lightstep-tracer-go",
        sum = "h1:vi1F1IQ8N7hNWytK9DpJsUfQhGuNSc19z330K6vl4zk=",
        version = "v0.18.1",
    )
    go_repository(
        name = "com_github_lucas_clemente_quic_go",
        importpath = "github.com/lucas-clemente/quic-go",
        sum = "h1:w8BBYUx5Z+kNpeaOeQW/KzcNsKWhh4O6PeQhb0nURPg=",
        version = "v0.19.2",
    )
    go_repository(
        name = "com_github_lunixbochs_vtclean",
        importpath = "github.com/lunixbochs/vtclean",
        sum = "h1:xu2sLAri4lGiovBDQKxl5mrXyESr3gUr5m5SM5+LVb8=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_lyft_protoc_gen_validate",
        importpath = "github.com/lyft/protoc-gen-validate",
        sum = "h1:KNt/RhmQTOLr7Aj8PsJ7mTronaFyx80mRTT9qF261dA=",
        version = "v0.0.13",
    )
    go_repository(
        name = "com_github_magiconair_properties",
        importpath = "github.com/magiconair/properties",
        sum = "h1:ZC2Vc7/ZFkGmsVC9KvOjumD+G5lXy2RtTKyzRKO2BQ4=",
        version = "v1.8.1",
    )
    go_repository(
        name = "com_github_mailru_easyjson",
        importpath = "github.com/mailru/easyjson",
        sum = "h1:UGYAvKxe3sBsEDzO8ZeWOSlIQfWFlxbzLZe7hwFURr0=",
        version = "v0.7.7",
    )
    go_repository(
        name = "com_github_marten_seemann_qpack",
        importpath = "github.com/marten-seemann/qpack",
        sum = "h1:jvTsT/HpCn2UZJdP+UUB53FfUUgeOyG5K1ns0OJOGVs=",
        version = "v0.2.1",
    )
    go_repository(
        name = "com_github_marten_seemann_qtls",
        importpath = "github.com/marten-seemann/qtls",
        sum = "h1:ECsuYUKalRL240rRD4Ri33ISb7kAQ3qGDlrrl55b2pc=",
        version = "v0.10.0",
    )
    go_repository(
        name = "com_github_marten_seemann_qtls_go1_15",
        importpath = "github.com/marten-seemann/qtls-go1-15",
        sum = "h1:LIH6K34bPVttyXnUWixk0bzH6/N07VxbSabxn5A5gZQ=",
        version = "v0.1.1",
    )
    go_repository(
        name = "com_github_matryer_moq",
        importpath = "github.com/matryer/moq",
        sum = "h1:HvFwW+cm9bCbZ/+vuGNq7CRWXql8c0y8nGeYpqmpvmk=",
        version = "v0.0.0-20190312154309-6cfb0558e1bd",
    )
    go_repository(
        name = "com_github_mattn_go_colorable",
        importpath = "github.com/mattn/go-colorable",
        sum = "h1:c1ghPdyEDarC70ftn0y+A/Ee++9zz8ljHG1b13eJ0s8=",
        version = "v0.1.8",
    )
    go_repository(
        name = "com_github_mattn_go_isatty",
        importpath = "github.com/mattn/go-isatty",
        sum = "h1:wuysRhFDzyxgEmMf5xjvJ2M9dZoWAXNNr5LSBS7uHXY=",
        version = "v0.0.12",
    )
    go_repository(
        name = "com_github_mattn_go_runewidth",
        importpath = "github.com/mattn/go-runewidth",
        sum = "h1:UnlwIPBGaTZfPQ6T1IGzPI0EkYAQmT9fAEJ/poFC63o=",
        version = "v0.0.2",
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
        name = "com_github_mdlayher_raw",
        importpath = "github.com/mdlayher/raw",
        sum = "h1:aFkJ6lx4FPip+S+Uw4aTegFMct9shDvP+79PsSxpm3w=",
        version = "v0.0.0-20191009151244-50f2db8cc065",
    )
    go_repository(
        name = "com_github_microcosm_cc_bluemonday",
        importpath = "github.com/microcosm-cc/bluemonday",
        sum = "h1:SIYunPjnlXcW+gVfvm0IlSeR5U3WZUOLfVmqg85Go44=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_miekg_dns",
        importpath = "github.com/miekg/dns",
        sum = "h1:9jZdLNd/P4+SfEJ0TNyxYpsK8N4GtfylBLqtbYN1sbA=",
        version = "v1.0.14",
    )
    go_repository(
        name = "com_github_mitchellh_cli",
        importpath = "github.com/mitchellh/cli",
        sum = "h1:iGBIsUe3+HZ/AD/Vd7DErOt5sU9fa8Uj7A2s1aggv1Y=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_mitchellh_go_homedir",
        importpath = "github.com/mitchellh/go-homedir",
        sum = "h1:lukF9ziXFxDFPkA1vsr5zpc1XuPDn/wFntq5mG+4E0Y=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_mitchellh_go_testing_interface",
        importpath = "github.com/mitchellh/go-testing-interface",
        sum = "h1:fzU/JVNcaqHQEcVFAKeR41fkiLdIPrefOvVG1VZ96U0=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_mitchellh_gox",
        importpath = "github.com/mitchellh/gox",
        sum = "h1:lfGJxY7ToLJQjHHwi0EX6uYBdK78egf954SQl13PQJc=",
        version = "v0.4.0",
    )
    go_repository(
        name = "com_github_mitchellh_iochan",
        importpath = "github.com/mitchellh/iochan",
        sum = "h1:C+X3KsSTLFVBr/tK1eYN/vs4rJcvsiLU338UhYPJWeY=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_mitchellh_mapstructure",
        importpath = "github.com/mitchellh/mapstructure",
        sum = "h1:fmNYVwqnSfB9mZU6OS2O6GsXM+wcskZDuKQzvN1EDeE=",
        version = "v1.1.2",
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
        name = "com_github_nats_io_jwt",
        importpath = "github.com/nats-io/jwt",
        sum = "h1:+RB5hMpXUUA2dfxuhBTEkMOrYmM+gKIZYS1KjSostMI=",
        version = "v0.3.2",
    )
    go_repository(
        name = "com_github_nats_io_nats_go",
        importpath = "github.com/nats-io/nats.go",
        sum = "h1:ik3HbLhZ0YABLto7iX80pZLPw/6dx3T+++MZJwLnMrQ=",
        version = "v1.9.1",
    )
    go_repository(
        name = "com_github_nats_io_nats_server_v2",
        importpath = "github.com/nats-io/nats-server/v2",
        sum = "h1:i2Ly0B+1+rzNZHHWtD4ZwKi+OU5l+uQo1iDHZ2PmiIc=",
        version = "v2.1.2",
    )
    go_repository(
        name = "com_github_nats_io_nkeys",
        importpath = "github.com/nats-io/nkeys",
        sum = "h1:6JrEfig+HzTH85yxzhSVbjHRJv9cn0p6n3IngIcM5/k=",
        version = "v0.1.3",
    )
    go_repository(
        name = "com_github_nats_io_nuid",
        importpath = "github.com/nats-io/nuid",
        sum = "h1:5iA8DT8V7q8WK2EScv2padNa/rTESc1KdnPw4TC2paw=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_github_neelance_astrewrite",
        importpath = "github.com/neelance/astrewrite",
        sum = "h1:D6paGObi5Wud7xg83MaEFyjxQB1W5bz5d0IFppr+ymk=",
        version = "v0.0.0-20160511093645-99348263ae86",
    )
    go_repository(
        name = "com_github_neelance_sourcemap",
        importpath = "github.com/neelance/sourcemap",
        sum = "h1:eFXv9Nu1lGbrNbj619aWwZfVF5HBrm9Plte8aNptuTI=",
        version = "v0.0.0-20151028013722-8c68805598ab",
    )
    go_repository(
        name = "com_github_niemeyer_pretty",
        importpath = "github.com/niemeyer/pretty",
        sum = "h1:fD57ERR4JtEqsWbfPhv4DMiApHyliiK5xCTNVSPiaAs=",
        version = "v0.0.0-20200227124842-a10e7caefd8e",
    )
    go_repository(
        name = "com_github_nxadm_tail",
        importpath = "github.com/nxadm/tail",
        replace = "github.com/lukedirtwalker/tail",
        sum = "h1:hNhCwj5i+kmlvj/als0kzOuEFhIOGs3pnfxTm0/G8X8=",
        version = "v1.3.1-0.20190919080739-7f7d37fab281",
    )
    go_repository(
        name = "com_github_oklog_oklog",
        importpath = "github.com/oklog/oklog",
        sum = "h1:wVfs8F+in6nTBMkA7CbRw+zZMIB7nNM825cM1wuzoTk=",
        version = "v0.3.2",
    )
    go_repository(
        name = "com_github_oklog_run",
        importpath = "github.com/oklog/run",
        sum = "h1:Ru7dDtJNOyC66gQ5dQmaCa0qIsAUFY3sFpK1Xk8igrw=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_oklog_ulid",
        importpath = "github.com/oklog/ulid",
        sum = "h1:EGfNDEx6MqHz8B3uNV6QAib1UR2Lm97sHi3ocA6ESJ4=",
        version = "v1.3.1",
    )
    go_repository(
        name = "com_github_olekukonko_tablewriter",
        importpath = "github.com/olekukonko/tablewriter",
        sum = "h1:58+kh9C6jJVXYjt8IE48G2eWl6BjwU5Gj0gqY84fy78=",
        version = "v0.0.0-20170122224234-a0225b3f23b5",
    )
    go_repository(
        name = "com_github_oneofone_xxhash",
        importpath = "github.com/OneOfOne/xxhash",
        sum = "h1:KMrpdQIwFcEqXDklaen+P1axHaj9BSKzvpUUfnHldSE=",
        version = "v1.2.2",
    )
    go_repository(
        name = "com_github_onsi_ginkgo",
        importpath = "github.com/onsi/ginkgo",
        sum = "h1:2mOpI4JVVPBN+WQRa0WKH2eXR+Ey+uK4n7Zj0aYpIQA=",
        version = "v1.14.0",
    )
    go_repository(
        name = "com_github_onsi_gomega",
        importpath = "github.com/onsi/gomega",
        sum = "h1:o0+MgICZLuZ7xjH7Vx6zS/zcu93/BEp1VwkIW1mEXCE=",
        version = "v1.10.1",
    )
    go_repository(
        name = "com_github_op_go_logging",
        importpath = "github.com/op/go-logging",
        sum = "h1:lDH9UUVJtmYCjyT0CI4q8xvlXPxeZ0gYCVvWbmPlp88=",
        version = "v0.0.0-20160315200505-970db520ece7",
    )
    go_repository(
        name = "com_github_opentracing_basictracer_go",
        importpath = "github.com/opentracing/basictracer-go",
        sum = "h1:YyUAhaEfjoWXclZVJ9sGoNct7j4TVk7lZWlQw5UXuoo=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_opentracing_contrib_go_observer",
        importpath = "github.com/opentracing-contrib/go-observer",
        sum = "h1:lM6RxxfUMrYL/f8bWEUqdXrANWtrL7Nndbm9iFN0DlU=",
        version = "v0.0.0-20170622124052-a52f23424492",
    )
    go_repository(
        name = "com_github_opentracing_opentracing_go",
        importpath = "github.com/opentracing/opentracing-go",
        sum = "h1:pWlfV3Bxv7k65HYwkikxat0+s3pV4bsqf19k25Ur8rU=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_openzipkin_contrib_zipkin_go_opentracing",
        importpath = "github.com/openzipkin-contrib/zipkin-go-opentracing",
        sum = "h1:ZCnq+JUrvXcDVhX/xRolRBZifmabN1HcS1wrPSvxhrU=",
        version = "v0.4.5",
    )
    go_repository(
        name = "com_github_openzipkin_zipkin_go",
        importpath = "github.com/openzipkin/zipkin-go",
        sum = "h1:nY8Hti+WKaP0cRsSeQ026wU03QsM762XBeCXBb9NAWI=",
        version = "v0.2.2",
    )
    go_repository(
        name = "com_github_pact_foundation_pact_go",
        importpath = "github.com/pact-foundation/pact-go",
        sum = "h1:OYkFijGHoZAYbOIb1LWXrwKQbMMRUv1oQ89blD2Mh2Q=",
        version = "v1.0.4",
    )
    go_repository(
        name = "com_github_pascaldekloe_goe",
        importpath = "github.com/pascaldekloe/goe",
        sum = "h1:Lgl0gzECD8GnQ5QCWA8o6BtfL6mDH5rQgM4/fX3avOs=",
        version = "v0.0.0-20180627143212-57f6aae5913c",
    )
    go_repository(
        name = "com_github_patrickmn_go_cache",
        importpath = "github.com/patrickmn/go-cache",
        sum = "h1:MUIwjEiAMYk8zkXXUQeb5itrXF+HpS2pfxNsA2a7AiY=",
        version = "v2.1.1-0.20180815053127-5633e0862627+incompatible",
    )
    go_repository(
        name = "com_github_pborman_uuid",
        importpath = "github.com/pborman/uuid",
        sum = "h1:J7Q5mO4ysT1dv8hyrUGHb9+ooztCXu1D8MY8DZYsu3g=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_pelletier_go_toml",
        importpath = "github.com/pelletier/go-toml",
        sum = "h1:0r6tAXtt8p5+IJtshL5f+5E/z0qH2aE89UmV4/tRF64=",
        version = "v1.8.1-0.20200708110244-34de94e6a887",
    )
    go_repository(
        name = "com_github_performancecopilot_speed",
        importpath = "github.com/performancecopilot/speed",
        sum = "h1:2WnRzIquHa5QxaJKShDkLM+sc0JPuwhXzK8OYOyt3Vg=",
        version = "v3.0.0+incompatible",
    )
    go_repository(
        name = "com_github_philhofer_fwd",
        importpath = "github.com/philhofer/fwd",
        sum = "h1:UbZqGr5Y38ApvM/V/jEljVxwocdweyH+vmYvRPBnbqQ=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_pierrec_lz4",
        importpath = "github.com/pierrec/lz4",
        sum = "h1:2xWsjqPFWcplujydGg4WmhC/6fZqK42wMM8aXeqhl0I=",
        version = "v2.0.5+incompatible",
    )
    go_repository(
        name = "com_github_pkg_errors",
        importpath = "github.com/pkg/errors",
        sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
        version = "v0.9.1",
    )
    go_repository(
        name = "com_github_pkg_profile",
        importpath = "github.com/pkg/profile",
        sum = "h1:F++O52m40owAmADcojzM+9gyjmMOY/T4oYJkgFDH8RE=",
        version = "v1.2.1",
    )
    go_repository(
        name = "com_github_pmezard_go_difflib",
        importpath = "github.com/pmezard/go-difflib",
        sum = "h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_posener_complete",
        importpath = "github.com/posener/complete",
        sum = "h1:ccV59UEOTzVDnDUEFdT95ZzHVZ+5+158q8+SJb2QV5w=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_prometheus_client_golang",
        importpath = "github.com/prometheus/client_golang",
        sum = "h1:YVPodQOcK15POxhgARIvnDRVpLcuK8mglnMrWfyrw6A=",
        version = "v1.6.0",
    )
    go_repository(
        name = "com_github_prometheus_client_model",
        importpath = "github.com/prometheus/client_model",
        sum = "h1:uq5h0d+GuxiXLJLNABMgp2qUWDPiLvgCzz2dUR+/W/M=",
        version = "v0.2.0",
    )
    go_repository(
        name = "com_github_prometheus_common",
        importpath = "github.com/prometheus/common",
        sum = "h1:KOMtN28tlbam3/7ZKEYKHhKoJZYYj3gMH4uc62x7X7U=",
        version = "v0.9.1",
    )
    go_repository(
        name = "com_github_prometheus_procfs",
        importpath = "github.com/prometheus/procfs",
        sum = "h1:DhHlBtkHWPYi8O2y31JkK0TF+DGM+51OopZjH/Ia5qI=",
        version = "v0.0.11",
    )
    go_repository(
        name = "com_github_prometheus_tsdb",
        importpath = "github.com/prometheus/tsdb",
        sum = "h1:YZcsG11NqnK4czYLrWd9mpEuAJIHVQLwdrleYfszMAA=",
        version = "v0.7.1",
    )
    go_repository(
        name = "com_github_rcrowley_go_metrics",
        importpath = "github.com/rcrowley/go-metrics",
        sum = "h1:9ZKAASQSHhDYGoxY8uLVpewe1GDZ2vu2Tr/vTdVAkFQ=",
        version = "v0.0.0-20181016184325-3113b8401b8a",
    )
    go_repository(
        name = "com_github_rogpeppe_fastuuid",
        importpath = "github.com/rogpeppe/fastuuid",
        sum = "h1:gu+uRPtBe88sKxUCEXRoeCvVG90TJmwhiqRpvdhQFng=",
        version = "v0.0.0-20150106093220-6724a57986af",
    )
    go_repository(
        name = "com_github_rogpeppe_go_internal",
        importpath = "github.com/rogpeppe/go-internal",
        sum = "h1:RR9dF3JtopPvtkroDZuVD7qquD0bnHlKSqaQhgwt8yk=",
        version = "v1.3.0",
    )
    go_repository(
        name = "com_github_russross_blackfriday",
        importpath = "github.com/russross/blackfriday",
        sum = "h1:HyvC0ARfnZBqnXwABFeSZHpKvJHJJfPz81GNueLj0oo=",
        version = "v1.5.2",
    )
    go_repository(
        name = "com_github_russross_blackfriday_v2",
        importpath = "github.com/russross/blackfriday/v2",
        sum = "h1:lPqVAte+HuHNfhJ/0LC98ESWRz8afy9tM/0RK8m9o+Q=",
        version = "v2.0.1",
    )
    go_repository(
        name = "com_github_ryanuber_columnize",
        importpath = "github.com/ryanuber/columnize",
        sum = "h1:UFr9zpz4xgTnIE5yIMtWAMngCdZ9p/+q6lTbgelo80M=",
        version = "v0.0.0-20160712163229-9b3edd62028f",
    )
    go_repository(
        name = "com_github_samuel_go_zookeeper",
        importpath = "github.com/samuel/go-zookeeper",
        sum = "h1:p3Vo3i64TCLY7gIfzeQaUJ+kppEO5WQG3cL8iE8tGHU=",
        version = "v0.0.0-20190923202752-2cc03de413da",
    )
    go_repository(
        name = "com_github_sean_seed",
        importpath = "github.com/sean-/seed",
        sum = "h1:nn5Wsu0esKSJiIVhscUtVbo7ada43DJhG55ua/hjS5I=",
        version = "v0.0.0-20170313163322-e2103e2c3529",
    )
    go_repository(
        name = "com_github_sergi_go_diff",
        importpath = "github.com/sergi/go-diff",
        sum = "h1:tB9NOR21++IjLyVx3/PCPhWMwqGNCMQEH96A6dMZ/gc=",
        version = "v1.0.1-0.20180205163309-da645544ed44",
    )
    go_repository(
        name = "com_github_shopify_sarama",
        importpath = "github.com/Shopify/sarama",
        sum = "h1:9oksLxC6uxVPHPVYUmq6xhr1BOF/hHobWH2UzO67z1s=",
        version = "v1.19.0",
    )
    go_repository(
        name = "com_github_shopify_toxiproxy",
        importpath = "github.com/Shopify/toxiproxy",
        sum = "h1:TKdv8HiTLgE5wdJuEML90aBgNWsokNbMijUGhmcoBJc=",
        version = "v2.1.4+incompatible",
    )
    go_repository(
        name = "com_github_shurcool_component",
        importpath = "github.com/shurcooL/component",
        sum = "h1:Fth6mevc5rX7glNLpbAMJnqKlfIkcTjZCSHEeqvKbcI=",
        version = "v0.0.0-20170202220835-f88ec8f54cc4",
    )
    go_repository(
        name = "com_github_shurcool_events",
        importpath = "github.com/shurcooL/events",
        sum = "h1:vabduItPAIz9px5iryD5peyx7O3Ya8TBThapgXim98o=",
        version = "v0.0.0-20181021180414-410e4ca65f48",
    )
    go_repository(
        name = "com_github_shurcool_github_flavored_markdown",
        importpath = "github.com/shurcooL/github_flavored_markdown",
        sum = "h1:qb9IthCFBmROJ6YBS31BEMeSYjOscSiG+EO+JVNTz64=",
        version = "v0.0.0-20181002035957-2122de532470",
    )
    go_repository(
        name = "com_github_shurcool_go",
        importpath = "github.com/shurcooL/go",
        sum = "h1:MZM7FHLqUHYI0Y/mQAt3d2aYa0SiNms/hFqC9qJYolM=",
        version = "v0.0.0-20180423040247-9e1955d9fb6e",
    )
    go_repository(
        name = "com_github_shurcool_go_goon",
        importpath = "github.com/shurcooL/go-goon",
        sum = "h1:llrF3Fs4018ePo4+G/HV/uQUqEI1HMDjCeOf2V6puPc=",
        version = "v0.0.0-20170922171312-37c2f522c041",
    )
    go_repository(
        name = "com_github_shurcool_gofontwoff",
        importpath = "github.com/shurcooL/gofontwoff",
        sum = "h1:Yoy/IzG4lULT6qZg62sVC+qyBL8DQkmD2zv6i7OImrc=",
        version = "v0.0.0-20180329035133-29b52fc0a18d",
    )
    go_repository(
        name = "com_github_shurcool_gopherjslib",
        importpath = "github.com/shurcooL/gopherjslib",
        sum = "h1:UOk+nlt1BJtTcH15CT7iNO7YVWTfTv/DNwEAQHLIaDQ=",
        version = "v0.0.0-20160914041154-feb6d3990c2c",
    )
    go_repository(
        name = "com_github_shurcool_highlight_diff",
        importpath = "github.com/shurcooL/highlight_diff",
        sum = "h1:vYEG87HxbU6dXj5npkeulCS96Dtz5xg3jcfCgpcvbIw=",
        version = "v0.0.0-20170515013008-09bb4053de1b",
    )
    go_repository(
        name = "com_github_shurcool_highlight_go",
        importpath = "github.com/shurcooL/highlight_go",
        sum = "h1:7pDq9pAMCQgRohFmd25X8hIH8VxmT3TaDm+r9LHxgBk=",
        version = "v0.0.0-20181028180052-98c3abbbae20",
    )
    go_repository(
        name = "com_github_shurcool_home",
        importpath = "github.com/shurcooL/home",
        sum = "h1:MPblCbqA5+z6XARjScMfz1TqtJC7TuTRj0U9VqIBs6k=",
        version = "v0.0.0-20181020052607-80b7ffcb30f9",
    )
    go_repository(
        name = "com_github_shurcool_htmlg",
        importpath = "github.com/shurcooL/htmlg",
        sum = "h1:crYRwvwjdVh1biHzzciFHe8DrZcYrVcZFlJtykhRctg=",
        version = "v0.0.0-20170918183704-d01228ac9e50",
    )
    go_repository(
        name = "com_github_shurcool_httperror",
        importpath = "github.com/shurcooL/httperror",
        sum = "h1:eHRtZoIi6n9Wo1uR+RU44C247msLWwyA89hVKwRLkMk=",
        version = "v0.0.0-20170206035902-86b7830d14cc",
    )
    go_repository(
        name = "com_github_shurcool_httpfs",
        importpath = "github.com/shurcooL/httpfs",
        sum = "h1:SWV2fHctRpRrp49VXJ6UZja7gU9QLHwRpIPBN89SKEo=",
        version = "v0.0.0-20171119174359-809beceb2371",
    )
    go_repository(
        name = "com_github_shurcool_httpgzip",
        importpath = "github.com/shurcooL/httpgzip",
        sum = "h1:fxoFD0in0/CBzXoyNhMTjvBZYW6ilSnTw7N7y/8vkmM=",
        version = "v0.0.0-20180522190206-b1c53ac65af9",
    )
    go_repository(
        name = "com_github_shurcool_issues",
        importpath = "github.com/shurcooL/issues",
        sum = "h1:T4wuULTrzCKMFlg3HmKHgXAF8oStFb/+lOIupLV2v+o=",
        version = "v0.0.0-20181008053335-6292fdc1e191",
    )
    go_repository(
        name = "com_github_shurcool_issuesapp",
        importpath = "github.com/shurcooL/issuesapp",
        sum = "h1:Y+TeIabU8sJD10Qwd/zMty2/LEaT9GNDaA6nyZf+jgo=",
        version = "v0.0.0-20180602232740-048589ce2241",
    )
    go_repository(
        name = "com_github_shurcool_notifications",
        importpath = "github.com/shurcooL/notifications",
        sum = "h1:TQVQrsyNaimGwF7bIhzoVC9QkKm4KsWd8cECGzFx8gI=",
        version = "v0.0.0-20181007000457-627ab5aea122",
    )
    go_repository(
        name = "com_github_shurcool_octicon",
        importpath = "github.com/shurcooL/octicon",
        sum = "h1:bu666BQci+y4S0tVRVjsHUeRon6vUXmsGBwdowgMrg4=",
        version = "v0.0.0-20181028054416-fa4f57f9efb2",
    )
    go_repository(
        name = "com_github_shurcool_reactions",
        importpath = "github.com/shurcooL/reactions",
        sum = "h1:LneqU9PHDsg/AkPDU3AkqMxnMYL+imaqkpflHu73us8=",
        version = "v0.0.0-20181006231557-f2e0b4ca5b82",
    )
    go_repository(
        name = "com_github_shurcool_sanitized_anchor_name",
        importpath = "github.com/shurcooL/sanitized_anchor_name",
        sum = "h1:PdmoCO6wvbs+7yrJyMORt4/BmY5IYyJwS/kOiWx8mHo=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_shurcool_users",
        importpath = "github.com/shurcooL/users",
        sum = "h1:YGaxtkYjb8mnTvtufv2LKLwCQu2/C7qFB7UtrOlTWOY=",
        version = "v0.0.0-20180125191416-49c67e49c537",
    )
    go_repository(
        name = "com_github_shurcool_webdavfs",
        importpath = "github.com/shurcooL/webdavfs",
        sum = "h1:JtcyT0rk/9PKOdnKQzuDR+FSjh7SGtJwpgVpfZBRKlQ=",
        version = "v0.0.0-20170829043945-18c3829fa133",
    )
    go_repository(
        name = "com_github_sirupsen_logrus",
        importpath = "github.com/sirupsen/logrus",
        sum = "h1:SPIRibHv4MatM3XXNO2BJeFLZwZ2LvZgfQ5+UNI2im4=",
        version = "v1.4.2",
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
        name = "com_github_soheilhy_cmux",
        importpath = "github.com/soheilhy/cmux",
        sum = "h1:0HKaf1o97UwFjHH9o5XsHUOF+tqmdA7KEzXLpiyaw0E=",
        version = "v0.1.4",
    )
    go_repository(
        name = "com_github_songgao_water",
        importpath = "github.com/songgao/water",
        sum = "h1:+y4hCMc/WKsDbAPsOQZgBSaSZ26uh2afyaWeVg/3s/c=",
        version = "v0.0.0-20190725173103-fd331bda3f4b",
    )
    go_repository(
        name = "com_github_sony_gobreaker",
        importpath = "github.com/sony/gobreaker",
        sum = "h1:oMnRNZXX5j85zso6xCPRNPtmAycat+WcoKbklScLDgQ=",
        version = "v0.4.1",
    )
    go_repository(
        name = "com_github_sourcegraph_annotate",
        importpath = "github.com/sourcegraph/annotate",
        sum = "h1:yKm7XZV6j9Ev6lojP2XaIshpT4ymkqhMeSghO5Ps00E=",
        version = "v0.0.0-20160123013949-f4cad6c6324d",
    )
    go_repository(
        name = "com_github_sourcegraph_syntaxhighlight",
        importpath = "github.com/sourcegraph/syntaxhighlight",
        sum = "h1:qpG93cPwA5f7s/ZPBJnGOYQNK/vKsaDaseuKT5Asee8=",
        version = "v0.0.0-20170531221838-bd320f5d308e",
    )
    go_repository(
        name = "com_github_spaolacci_murmur3",
        importpath = "github.com/spaolacci/murmur3",
        sum = "h1:qLC7fQah7D6K1B0ujays3HV9gkFtllcxhzImRR7ArPQ=",
        version = "v0.0.0-20180118202830-f09979ecbc72",
    )
    go_repository(
        name = "com_github_spf13_afero",
        importpath = "github.com/spf13/afero",
        sum = "h1:m8/z1t7/fwjysjQRYbP0RD+bUIF/8tJwPdEZsI83ACI=",
        version = "v1.1.2",
    )
    go_repository(
        name = "com_github_spf13_cast",
        importpath = "github.com/spf13/cast",
        sum = "h1:oget//CVOEoFewqQxwr0Ej5yjygnqGkvggSE/gB35Q8=",
        version = "v1.3.0",
    )
    go_repository(
        name = "com_github_spf13_cobra",
        importpath = "github.com/spf13/cobra",
        sum = "h1:KfztREH0tPxJJ+geloSLaAkaPkr4ki2Er5quFV1TDo4=",
        version = "v1.1.1",
    )
    go_repository(
        name = "com_github_spf13_jwalterweatherman",
        importpath = "github.com/spf13/jwalterweatherman",
        sum = "h1:XHEdyB+EcvlqZamSM4ZOMGlc93t6AcsBEu9Gc1vn7yk=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_spf13_pflag",
        importpath = "github.com/spf13/pflag",
        sum = "h1:iy+VFUOCP1a+8yFto/drg2CJ5u0yRoB7fZw3DKv/JXA=",
        version = "v1.0.5",
    )
    go_repository(
        name = "com_github_spf13_viper",
        importpath = "github.com/spf13/viper",
        sum = "h1:pM5oEahlgWv/WnHXpgbKz7iLIxRf65tye2Ci+XFK5sk=",
        version = "v1.7.1",
    )
    go_repository(
        name = "com_github_streadway_amqp",
        importpath = "github.com/streadway/amqp",
        sum = "h1:WhxRHzgeVGETMlmVfqhRn8RIeeNoPr2Czh33I4Zdccw=",
        version = "v0.0.0-20190827072141-edfb9018d271",
    )
    go_repository(
        name = "com_github_streadway_handy",
        importpath = "github.com/streadway/handy",
        sum = "h1:AhmOdSHeswKHBjhsLs/7+1voOxT+LLrSk/Nxvk35fug=",
        version = "v0.0.0-20190108123426-d5acb3125c2a",
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
        sum = "h1:hDPOHmpOpP40lSULcqw7IrRb/u7w6RpDC9399XyoNd0=",
        version = "v1.6.1",
    )
    go_repository(
        name = "com_github_subosito_gotenv",
        importpath = "github.com/subosito/gotenv",
        sum = "h1:Slr1R9HxAlEKefgq5jn9U+DnETlIUa6HfgEzj0g5d7s=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_tarm_serial",
        importpath = "github.com/tarm/serial",
        sum = "h1:UyzmZLoiDWMRywV4DUYb9Fbt8uiOSooupjTq10vpvnU=",
        version = "v0.0.0-20180830185346-98f6abe2eb07",
    )
    go_repository(
        name = "com_github_tinylib_msgp",
        importpath = "github.com/tinylib/msgp",
        sum = "h1:9fQd+ICuRIu/ue4vxJZu6/LzxN0HwMds2nq/0cFvxHU=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_github_tmc_grpc_websocket_proxy",
        importpath = "github.com/tmc/grpc-websocket-proxy",
        sum = "h1:LnC5Kc/wtumK+WB441p7ynQJzVuNRJiqddSIE3IlSEQ=",
        version = "v0.0.0-20190109142713-0ad062ec5ee5",
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
        name = "com_github_urfave_cli",
        importpath = "github.com/urfave/cli",
        sum = "h1:+mkCCcOFKPnCmVYVcURKps1Xe+3zP90gSYGNfRkjoIY=",
        version = "v1.22.1",
    )
    go_repository(
        name = "com_github_valyala_bytebufferpool",
        importpath = "github.com/valyala/bytebufferpool",
        sum = "h1:GqA5TC/0021Y/b9FG4Oi9Mr3q7XYx6KllzawFIhcdPw=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_valyala_fasttemplate",
        importpath = "github.com/valyala/fasttemplate",
        sum = "h1:TVEnxayobAdVkhQfrfes2IzOB6o+z4roRkPF52WA1u4=",
        version = "v1.2.1",
    )
    go_repository(
        name = "com_github_viant_assertly",
        importpath = "github.com/viant/assertly",
        sum = "h1:5x1GzBaRteIwTr5RAGFVG14uNeRFxVNbXPWrK2qAgpc=",
        version = "v0.4.8",
    )
    go_repository(
        name = "com_github_viant_toolbox",
        importpath = "github.com/viant/toolbox",
        sum = "h1:6TteTDQ68CjgcCe8wH3D3ZhUQQOJXMTbj/D9rkk2a1k=",
        version = "v0.24.0",
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
        name = "com_github_vividcortex_gohistogram",
        importpath = "github.com/VividCortex/gohistogram",
        sum = "h1:6+hBz+qvs0JOrrNhhmR7lFxo5sINxBCGXrdtl/UvroE=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_github_xeipuuv_gojsonpointer",
        importpath = "github.com/xeipuuv/gojsonpointer",
        sum = "h1:J9EGpcZtP0E/raorCMxlFGSTBrsSlaDGf3jU/qvAE2c=",
        version = "v0.0.0-20180127040702-4e3ac2762d5f",
    )
    go_repository(
        name = "com_github_xeipuuv_gojsonreference",
        importpath = "github.com/xeipuuv/gojsonreference",
        sum = "h1:EzJWgHovont7NscjpAxXsDA8S8BMYve8Y5+7cuRE7R0=",
        version = "v0.0.0-20180127040603-bd5ef7bd5415",
    )
    go_repository(
        name = "com_github_xeipuuv_gojsonschema",
        importpath = "github.com/xeipuuv/gojsonschema",
        sum = "h1:LhYJRs+L4fBtjZUfuSZIKGeVu0QRy8e5Xi7D17UxZ74=",
        version = "v1.2.0",
    )
    go_repository(
        name = "com_github_xiang90_probing",
        importpath = "github.com/xiang90/probing",
        sum = "h1:eY9dn8+vbi4tKz5Qo6v2eYzo7kUS51QINcR5jNpbZS8=",
        version = "v0.0.0-20190116061207-43a291ad63a2",
    )
    go_repository(
        name = "com_github_yuin_goldmark",
        importpath = "github.com/yuin/goldmark",
        sum = "h1:ruQGxdhGHe7FWOJPT0mKs5+pD2Xs1Bm/kdGlHO04FmM=",
        version = "v1.2.1",
    )
    go_repository(
        name = "com_google_cloud_go",
        importpath = "cloud.google.com/go",
        sum = "h1:AVXDdKsrtX33oR9fbCMu/+c1o8Ofjq6Ku/MInaLVg5Y=",
        version = "v0.46.3",
    )
    go_repository(
        name = "com_google_cloud_go_bigquery",
        importpath = "cloud.google.com/go/bigquery",
        sum = "h1:hL+ycaJpVE9M7nLoiXb/Pn10ENE2u+oddxbD8uu0ZVU=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_google_cloud_go_datastore",
        importpath = "cloud.google.com/go/datastore",
        sum = "h1:Kt+gOPPp2LEPWp8CSfxhsM8ik9CcyE/gYu+0r+RnZvM=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_google_cloud_go_firestore",
        importpath = "cloud.google.com/go/firestore",
        sum = "h1:9x7Bx0A9R5/M9jibeJeZWqjeVEIxYW9fZYqB9a70/bY=",
        version = "v1.1.0",
    )
    go_repository(
        name = "com_google_cloud_go_pubsub",
        importpath = "cloud.google.com/go/pubsub",
        sum = "h1:W9tAK3E57P75u0XLLR82LZyw8VpAnhmyTOxW9qzmyj8=",
        version = "v1.0.1",
    )
    go_repository(
        name = "com_google_cloud_go_storage",
        importpath = "cloud.google.com/go/storage",
        sum = "h1:VV2nUM3wwLLGh9lSABFgZMjInyUbJeaRSE64WuAIQ+4=",
        version = "v1.0.0",
    )
    go_repository(
        name = "com_shuralyov_dmitri_app_changes",
        importpath = "dmitri.shuralyov.com/app/changes",
        sum = "h1:hJiie5Bf3QucGRa4ymsAUOxyhYwGEz1xrsVk0P8erlw=",
        version = "v0.0.0-20180602232624-0a106ad413e3",
    )
    go_repository(
        name = "com_shuralyov_dmitri_gpu_mtl",
        importpath = "dmitri.shuralyov.com/gpu/mtl",
        sum = "h1:VpgP7xuJadIUuKccphEpTJnWhS2jkQyMt6Y7pJCD7fY=",
        version = "v0.0.0-20190408044501-666a987793e9",
    )
    go_repository(
        name = "com_shuralyov_dmitri_html_belt",
        importpath = "dmitri.shuralyov.com/html/belt",
        sum = "h1:SPOUaucgtVls75mg+X7CXigS71EnsfVUK/2CgVrwqgw=",
        version = "v0.0.0-20180602232347-f7d459c86be0",
    )
    go_repository(
        name = "com_shuralyov_dmitri_service_change",
        importpath = "dmitri.shuralyov.com/service/change",
        sum = "h1:GvWw74lx5noHocd+f6HBMXK6DuggBB1dhVkuGZbv7qM=",
        version = "v0.0.0-20181023043359-a85b471d5412",
    )
    go_repository(
        name = "com_shuralyov_dmitri_state",
        importpath = "dmitri.shuralyov.com/state",
        sum = "h1:ivON6cwHK1OH26MZyWDCnbTRZZf0IhNsENoNAKFS1g4=",
        version = "v0.0.0-20180228185332-28bcc343414c",
    )
    go_repository(
        name = "com_sourcegraph_sourcegraph_appdash",
        importpath = "sourcegraph.com/sourcegraph/appdash",
        sum = "h1:ucqkfpjg9WzSUubAO62csmucvxl4/JeW3F4I4909XkM=",
        version = "v0.0.0-20190731080439-ebfcffb1b5c0",
    )
    go_repository(
        name = "com_sourcegraph_sourcegraph_go_diff",
        importpath = "sourcegraph.com/sourcegraph/go-diff",
        sum = "h1:eTiIR0CoWjGzJcnQ3OkhIl/b9GJovq4lSAVRt0ZFEG8=",
        version = "v0.5.0",
    )
    go_repository(
        name = "com_sourcegraph_sqs_pbtypes",
        importpath = "sourcegraph.com/sqs/pbtypes",
        sum = "h1:JPJh2pk3+X4lXAkZIk2RuE/7/FoK9maXw+TNPJhVS/c=",
        version = "v0.0.0-20180604144634-d3ebe8f20ae4",
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
        sum = "h1:BLraFXnmrev5lT+xlilqcH8XK9/i0At2xKjWk4p6zsU=",
        version = "v1.0.0-20200227125254-8fa46927fb4f",
    )
    go_repository(
        name = "in_gopkg_cheggaaa_pb_v1",
        importpath = "gopkg.in/cheggaaa/pb.v1",
        sum = "h1:Ev7yu1/f6+d+b3pi5vPdRPc6nNtP1umSfcWiEfRqv6I=",
        version = "v1.0.25",
    )
    go_repository(
        name = "in_gopkg_errgo_v2",
        importpath = "gopkg.in/errgo.v2",
        sum = "h1:0vLT13EuvQ0hNvakwLuFZ/jYrLp5F3kcWHXdRggjCE8=",
        version = "v2.1.0",
    )
    go_repository(
        name = "in_gopkg_fsnotify_v1",
        importpath = "gopkg.in/fsnotify.v1",
        sum = "h1:xOHLXZwVvI9hhs+cLKq5+I5onOuwQLhQwiu63xxlHs4=",
        version = "v1.4.7",
    )
    go_repository(
        name = "in_gopkg_gcfg_v1",
        importpath = "gopkg.in/gcfg.v1",
        sum = "h1:m8OOJ4ccYHnx2f4gQwpno8nAX5OGOh7RLaaz0pj3Ogs=",
        version = "v1.2.3",
    )
    go_repository(
        name = "in_gopkg_inf_v0",
        importpath = "gopkg.in/inf.v0",
        sum = "h1:73M5CoZyi3ZLMOyDlQh031Cx6N9NDJ2Vvfl76EDAgDc=",
        version = "v0.9.1",
    )
    go_repository(
        name = "in_gopkg_ini_v1",
        importpath = "gopkg.in/ini.v1",
        sum = "h1:AQvPpx3LzTDM0AjnIRlVFwFFGC+npRopjZxLJj6gdno=",
        version = "v1.51.0",
    )
    go_repository(
        name = "in_gopkg_resty_v1",
        importpath = "gopkg.in/resty.v1",
        sum = "h1:CuXP0Pjfw9rOuY6EP+UvtNvt5DSqHpIxILZKT/quCZI=",
        version = "v1.12.0",
    )
    go_repository(
        name = "in_gopkg_tomb_v1",
        importpath = "gopkg.in/tomb.v1",
        sum = "h1:uRGJdciOHaEIrze2W8Q3AKkepLTh2hOroT7a+7czfdQ=",
        version = "v1.0.0-20141024135613-dd632973f1e7",
    )
    go_repository(
        name = "in_gopkg_warnings_v0",
        importpath = "gopkg.in/warnings.v0",
        sum = "h1:wFXVbFY8DY5/xOe1ECiWdKCzZlxgshcYVNkBHstARME=",
        version = "v0.1.2",
    )
    go_repository(
        name = "in_gopkg_yaml_v2",
        importpath = "gopkg.in/yaml.v2",
        sum = "h1:D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=",
        version = "v2.4.0",
    )
    go_repository(
        name = "in_gopkg_yaml_v3",
        importpath = "gopkg.in/yaml.v3",
        sum = "h1:tQIYjPdBoyREyB9XMu+nnTclpTYkz2zFM+lzLJFO4gQ=",
        version = "v3.0.0-20200615113413-eeeca48fe776",
    )
    go_repository(
        name = "io_etcd_go_bbolt",
        importpath = "go.etcd.io/bbolt",
        sum = "h1:MUGmc65QhB3pIlaQ5bB4LwqSj6GIonVJXpZiaKNyaKk=",
        version = "v1.3.3",
    )
    go_repository(
        name = "io_etcd_go_etcd",
        importpath = "go.etcd.io/etcd",
        sum = "h1:VcrIfasaLFkyjk6KNlXQSzO+B0fZcnECiDrKJsfxka0=",
        version = "v0.0.0-20191023171146-3cf2f69b5738",
    )
    go_repository(
        name = "io_k8s_sigs_yaml",
        importpath = "sigs.k8s.io/yaml",
        sum = "h1:4A07+ZFc2wgJwo8YNlQpr1rVlgUDlxXHhPJciaPY5gs=",
        version = "v1.1.0",
    )
    go_repository(
        name = "io_opencensus_go",
        importpath = "go.opencensus.io",
        sum = "h1:75k/FF0Q2YM8QYo07VPddOLBslDt1MZOdEslOHvmzAs=",
        version = "v0.22.2",
    )
    go_repository(
        name = "io_rsc_binaryregexp",
        importpath = "rsc.io/binaryregexp",
        sum = "h1:HfqmD5MEmC0zvwBuF187nq9mdnXjXsSivRiXN7SmRkE=",
        version = "v0.2.0",
    )
    go_repository(
        name = "io_rsc_quote_v3",
        importpath = "rsc.io/quote/v3",
        sum = "h1:9JKUTTIUgS6kzR9mK1YuGKv6Nl+DijDNIc0ghT58FaY=",
        version = "v3.1.0",
    )
    go_repository(
        name = "io_rsc_sampler",
        importpath = "rsc.io/sampler",
        sum = "h1:7uVkIFmeBqHfdjD+gZwtXXI+RODJ2Wc4O7MPEh/QiW4=",
        version = "v1.3.0",
    )
    go_repository(
        name = "org_apache_git_thrift_git",
        importpath = "git.apache.org/thrift.git",
        sum = "h1:OR8VhtwhcAI3U48/rzBsVOuHi0zDPzYI1xASVcdSgR8=",
        version = "v0.0.0-20180902110319-2566ecd5d999",
    )
    go_repository(
        name = "org_go4",
        importpath = "go4.org",
        sum = "h1:+hE86LblG4AyDgwMCLTE6FOlM9+qjHSYS+rKqxUVdsM=",
        version = "v0.0.0-20180809161055-417644f6feb5",
    )
    go_repository(
        name = "org_go4_grpc",
        importpath = "grpc.go4.org",
        sum = "h1:tmXTu+dfa+d9Evp8NpJdgOy6+rt8/x4yG7qPBrtNfLY=",
        version = "v0.0.0-20170609214715-11d0a25b4919",
    )
    go_repository(
        name = "org_golang_google_api",
        importpath = "google.golang.org/api",
        sum = "h1:Q3Ui3V3/CVinFWFiW39Iw0kMuVrRzYX0wN6OPFp0lTA=",
        version = "v0.13.0",
    )
    go_repository(
        name = "org_golang_google_appengine",
        importpath = "google.golang.org/appengine",
        sum = "h1:QzqyMA1tlu6CgqCDUtU9V+ZKhLFT2dkJuANu5QaxI3I=",
        version = "v1.6.1",
    )
    go_repository(
        name = "org_golang_google_genproto",
        importpath = "google.golang.org/genproto",
        sum = "h1:Ob5/580gVHBJZgXnff1cZDbG+xLtMVE5mDRTe+nIsX4=",
        version = "v0.0.0-20191108220845-16a3f7862a1a",
    )
    go_repository(
        name = "org_golang_google_grpc",
        importpath = "google.golang.org/grpc",
        sum = "h1:EC2SB8S04d2r73uptxphDSUG+kTKVgjRPF+N3xpxRB4=",
        version = "v1.29.1",
    )
    go_repository(
        name = "org_golang_google_protobuf",
        importpath = "google.golang.org/protobuf",
        sum = "h1:4MY060fB1DLGMB/7MBTLnwQUY6+F09GEiz6SsrNqyzM=",
        version = "v1.23.0",
    )
    go_repository(
        name = "org_golang_x_build",
        importpath = "golang.org/x/build",
        sum = "h1:E2M5QgjZ/Jg+ObCQAudsXxuTsLj7Nl5RV/lZcQZmKSo=",
        version = "v0.0.0-20190111050920-041ab4dc3f9d",
    )
    go_repository(
        name = "org_golang_x_crypto",
        importpath = "golang.org/x/crypto",
        sum = "h1:/ZScEX8SfEmUGRHs0gxpqteO5nfNW6axyZbBdw9A12g=",
        version = "v0.0.0-20210220033148-5ea612d1eb83",
    )
    go_repository(
        name = "org_golang_x_exp",
        importpath = "golang.org/x/exp",
        sum = "h1:A1gGSx58LAGVHUUsOf7IiR0u8Xb6W51gRwfDBhkdcaw=",
        version = "v0.0.0-20191030013958-a1ab85dbe136",
    )
    go_repository(
        name = "org_golang_x_image",
        importpath = "golang.org/x/image",
        sum = "h1:+qEpEAPhDZ1o0x3tHzZTQDArnOixOzGD9HUJfcg0mb4=",
        version = "v0.0.0-20190802002840-cff245a6509b",
    )
    go_repository(
        name = "org_golang_x_lint",
        importpath = "golang.org/x/lint",
        sum = "h1:5hukYrvBGR8/eNkX5mdUezrA6JiaEZDtJb9Ei+1LlBs=",
        version = "v0.0.0-20190930215403-16217165b5de",
    )
    go_repository(
        name = "org_golang_x_mobile",
        importpath = "golang.org/x/mobile",
        sum = "h1:4+4C/Iv2U4fMZBiMCc98MG1In4gJY5YRhtpDNeDeHWs=",
        version = "v0.0.0-20190719004257-d2bd2a29d028",
    )
    go_repository(
        name = "org_golang_x_mod",
        importpath = "golang.org/x/mod",
        sum = "h1:Kvvh58BN8Y9/lBi7hTekvtMpm07eUZ0ck5pRHpsMWrY=",
        version = "v0.4.1",
    )
    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net",
        sum = "h1:Ugb8sMTWuWRC3+sz5WeN/4kejDx9BvIwnPUiJBjJE+8=",
        version = "v0.0.0-20210505024714-0287a6fb4125",
    )
    go_repository(
        name = "org_golang_x_oauth2",
        importpath = "golang.org/x/oauth2",
        sum = "h1:SVwTIAaPC2U/AvvLNZ2a7OVsmBpC8L5BlwK1whH3hm0=",
        version = "v0.0.0-20190604053449-0f29369cfe45",
    )
    go_repository(
        name = "org_golang_x_perf",
        importpath = "golang.org/x/perf",
        sum = "h1:xYq6+9AtI+xP3M4r0N1hCkHrInHDBohhquRgx9Kk6gI=",
        version = "v0.0.0-20180704124530-6e6d33e29852",
    )
    go_repository(
        name = "org_golang_x_sync",
        importpath = "golang.org/x/sync",
        sum = "h1:SQFwaSi55rU7vdNs9Yr0Z324VNlrF+0wMqRXT4St8ck=",
        version = "v0.0.0-20201020160332-67f06af15bc9",
    )
    go_repository(
        name = "org_golang_x_term",
        importpath = "golang.org/x/term",
        sum = "h1:v+OssWQX+hTHEmOBgwxdZxK4zHq3yOs8F9J7mk0PY8E=",
        version = "v0.0.0-20201126162022-7de9c90e9dd1",
    )
    go_repository(
        name = "org_golang_x_text",
        importpath = "golang.org/x/text",
        sum = "h1:aRYxNxv6iGQlyVaZmk6ZgYEDa+Jg18DxebPSrd6bg1M=",
        version = "v0.3.6",
    )
    go_repository(
        name = "org_golang_x_time",
        importpath = "golang.org/x/time",
        sum = "h1:O8mE0/t419eoIwhTFpKVkHiTs/Igowgfkj25AcZrtiE=",
        version = "v0.0.0-20210220033141-f8bda1e9f3ba",
    )
    go_repository(
        name = "org_golang_x_tools",
        importpath = "golang.org/x/tools",
        sum = "h1:po9/4sTYwZU9lPhi1tOrb4hCv3qrhiQ77LZfGa2OjwY=",
        version = "v0.1.0",
    )
    go_repository(
        name = "org_golang_x_xerrors",
        importpath = "golang.org/x/xerrors",
        sum = "h1:go1bK/D/BFZV2I8cIQd1NKEZ+0owSTG1fDTci4IqFcE=",
        version = "v0.0.0-20200804184101-5ec99f83aff1",
    )
    go_repository(
        name = "org_uber_go_atomic",
        importpath = "go.uber.org/atomic",
        sum = "h1:Ezj3JGmsOnG1MoRWQkPBsKLe9DwWD9QeXzTRzzldNVk=",
        version = "v1.6.0",
    )
    go_repository(
        name = "org_uber_go_goleak",
        importpath = "go.uber.org/goleak",
        sum = "h1:z+mqJhf6ss6BSfSM671tgKyZBFPTTJM+HLxnhPC3wu0=",
        version = "v1.1.10",
    )
    go_repository(
        name = "org_uber_go_multierr",
        importpath = "go.uber.org/multierr",
        sum = "h1:KCa4XfM8CWFCpxXRGok+Q0SS/0XBhMDbHHGABQLvD2A=",
        version = "v1.5.0",
    )
    go_repository(
        name = "org_uber_go_tools",
        importpath = "go.uber.org/tools",
        sum = "h1:0mgffUl7nfd+FpvXMVz4IDEaUSmT1ysygQC7qYo7sG4=",
        version = "v0.0.0-20190618225709-2cfd321de3ee",
    )
    go_repository(
        name = "org_uber_go_zap",
        importpath = "go.uber.org/zap",
        sum = "h1:uFRZXykJGK9lLY4HtgSw44DnIcAM+kRBP7x5m+NpAOM=",
        version = "v1.16.0",
    )

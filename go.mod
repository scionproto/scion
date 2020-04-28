module github.com/scionproto/scion

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/antlr/antlr4 v0.0.0-20181218183524-be58ebffde8e
	github.com/buildkite/go-buildkite v2.2.1-0.20190413010238-568b6651b687+incompatible
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/codahale/hdrhistogram v0.0.0-20161010025455-3a0bb77429bd // indirect
	github.com/dchest/cmac v0.0.0-20150527144652-62ff55a1048c
	github.com/golang/mock v1.4.0
	github.com/golang/protobuf v1.4.0 // indirect
	github.com/google/go-cmp v0.4.0
	github.com/google/go-querystring v1.0.1-0.20190318165438-c8c88dbee036 // indirect
	github.com/google/gopacket v1.1.16-0.20190123011826-102d5ca2098c
	github.com/iancoleman/strcase v0.0.0-20190422225806-e506e3ef7365
	github.com/inconshreveable/log15 v0.0.0-20161013181240-944cbfb97b44
	github.com/kormat/fmt15 v0.0.0-20181112140556-ee69fecb2656
	github.com/lucas-clemente/quic-go v0.15.5
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/mattn/go-isatty v0.0.8
	github.com/mattn/go-sqlite3 v1.9.1-0.20180719091609-b3511bfdd742
	github.com/opentracing/opentracing-go v1.1.0
	github.com/patrickmn/go-cache v2.1.1-0.20180815053127-5633e0862627+incompatible
	github.com/pkg/errors v0.8.2-0.20190227000051-27936f6d90f9 // indirect
	github.com/prometheus/client_golang v1.1.0
	github.com/prometheus/client_model v0.0.0-20190812154241-14fe0d1b01d4 // indirect
	github.com/sergi/go-diff v1.0.1-0.20180205163309-da645544ed44
	github.com/smartystreets/goconvey v1.6.4
	github.com/songgao/water v0.0.0-20190725173103-fd331bda3f4b
	github.com/spf13/cobra v1.0.0
	github.com/stretchr/testify v1.3.1-0.20190311161405-34c6fa2dc709
	github.com/syndtr/gocapability v0.0.0-20160928074757-e7cb7fa329f4
	github.com/uber/jaeger-client-go v2.20.1+incompatible
	github.com/uber/jaeger-lib v2.0.0+incompatible // indirect
	github.com/vishvananda/netlink v0.0.0-20170924180554-177f1ceba557
	github.com/vishvananda/netns v0.0.0-20170219233438-54f0e4339ce7 // indirect
	go.uber.org/atomic v1.5.1 // indirect
	golang.org/x/crypto v0.0.0-20200423211502-4bdfaf469ed5
	golang.org/x/net v0.0.0-20191105084925-a882066a44e0
	golang.org/x/tools v0.0.0-20191029041327-9cc4af7d6b2c
	gopkg.in/natefinch/lumberjack.v2 v2.0.0-20170531160350-a96e63847dc3
	gopkg.in/restruct.v1 v1.0.0-20151213023948-80ede2e57cc2
	gopkg.in/yaml.v2 v2.2.4
	zombiezen.com/go/capnproto2 v0.0.0-20190813022230-ddfb9bb855fa
)

replace github.com/smartystreets/goconvey => github.com/kormat/goconvey v0.0.0-20191113114839-63cc4eee0dbc

go 1.13

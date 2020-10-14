module github.com/scionproto/scion

require (
	github.com/antlr/antlr4 v0.0.0-20181218183524-be58ebffde8e
	github.com/buildkite/go-buildkite v2.2.1-0.20190413010238-568b6651b687+incompatible
	github.com/dchest/cmac v0.0.0-20150527144652-62ff55a1048c
	github.com/fatih/color v1.9.0
	github.com/go-kit/kit v0.10.0
	github.com/golang/mock v1.4.0
	github.com/golang/protobuf v1.4.0
	github.com/google/go-cmp v0.4.0
	github.com/google/go-querystring v1.0.1-0.20190318165438-c8c88dbee036 // indirect
	github.com/google/gopacket v1.1.16-0.20190123011826-102d5ca2098c
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.1-0.20190118093823-f849b5445de4
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20180507213350-8e809c8a8645
	github.com/iancoleman/strcase v0.0.0-20190422225806-e506e3ef7365
	github.com/kr/pretty v0.2.0 // indirect
	github.com/lucas-clemente/quic-go v0.17.3
	github.com/mattn/go-colorable v0.1.6 // indirect
	github.com/mattn/go-isatty v0.0.12
	github.com/mattn/go-sqlite3 v1.9.1-0.20180719091609-b3511bfdd742
	github.com/mdlayher/raw v0.0.0-20191009151244-50f2db8cc065 // indirect
	github.com/opentracing/opentracing-go v1.1.0
	github.com/patrickmn/go-cache v2.1.1-0.20180815053127-5633e0862627+incompatible
	github.com/pelletier/go-toml v1.8.1-0.20200708110244-34de94e6a887
	github.com/pkg/errors v0.9.1 // indirect
	github.com/prometheus/client_golang v1.6.0
	github.com/sergi/go-diff v1.0.1-0.20180205163309-da645544ed44
	github.com/smartystreets/goconvey v1.6.4
	github.com/songgao/water v0.0.0-20190725173103-fd331bda3f4b
	github.com/spf13/cobra v1.0.0
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/testify v1.5.1
	github.com/syndtr/gocapability v0.0.0-20160928074757-e7cb7fa329f4
	github.com/uber/jaeger-client-go v2.20.1+incompatible
	github.com/uber/jaeger-lib v2.0.0+incompatible // indirect
	github.com/vishvananda/netlink v0.0.0-20170924180554-177f1ceba557
	github.com/vishvananda/netns v0.0.0-20170219233438-54f0e4339ce7 // indirect
	go.uber.org/zap v1.16.0
	golang.org/x/crypto v0.0.0-20200820211705-5c72a883971a
	golang.org/x/net v0.0.0-20200927032502-5d4f70055728
	golang.org/x/text v0.3.3 // indirect
	golang.org/x/tools v0.0.0-20200929223013-bf155c11ec6f
	google.golang.org/genproto v0.0.0-20191002211648-c459b9ce5143 // indirect
	google.golang.org/grpc v1.29.1
	google.golang.org/protobuf v1.23.0
	gopkg.in/yaml.v2 v2.3.0
	zombiezen.com/go/capnproto2 v0.0.0-20190813022230-ddfb9bb855fa
)

replace github.com/nxadm/tail => github.com/lukedirtwalker/tail v1.3.1-0.20190919080739-7f7d37fab281

replace github.com/smartystreets/goconvey => github.com/kormat/goconvey v0.0.0-20191113114839-63cc4eee0dbc

go 1.14

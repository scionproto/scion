module github.com/scionproto/scion

require (
	github.com/antlr/antlr4 v0.0.0-20181218183524-be58ebffde8e
	github.com/bazelbuild/rules_go v0.27.0
	github.com/buildkite/go-buildkite/v2 v2.8.1
	github.com/dchest/cmac v0.0.0-20150527144652-62ff55a1048c
	github.com/deepmap/oapi-codegen v1.6.1
	github.com/fatih/color v1.9.0
	github.com/getkin/kin-openapi v0.53.0
	github.com/go-chi/chi/v5 v5.0.2
	github.com/go-chi/cors v1.1.1
	github.com/go-kit/kit v0.10.0
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.6
	github.com/google/go-containerregistry v0.5.1
	github.com/google/go-querystring v1.0.1-0.20190318165438-c8c88dbee036 // indirect
	github.com/google/gopacket v1.1.16-0.20190123011826-102d5ca2098c
	github.com/grpc-ecosystem/go-grpc-middleware v1.0.1-0.20190118093823-f849b5445de4
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0
	github.com/grpc-ecosystem/grpc-opentracing v0.0.0-20180507213350-8e809c8a8645
	github.com/iancoleman/strcase v0.0.0-20190422225806-e506e3ef7365
	github.com/lestrrat-go/jwx v1.1.5
	github.com/lucas-clemente/quic-go v0.21.1
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-isatty v0.0.12
	github.com/mattn/go-sqlite3 v1.14.4
	github.com/mdlayher/raw v0.0.0-20191009151244-50f2db8cc065 // indirect
	github.com/opentracing/opentracing-go v1.2.0
	github.com/patrickmn/go-cache v2.1.1-0.20180815053127-5633e0862627+incompatible
	github.com/pelletier/go-toml v1.9.3
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.7.1
	github.com/sergi/go-diff v1.0.1-0.20180205163309-da645544ed44
	github.com/smartystreets/goconvey v1.6.4
	github.com/songgao/water v0.0.0-20190725173103-fd331bda3f4b
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/uber/jaeger-client-go v2.29.1+incompatible
	github.com/uber/jaeger-lib v2.0.0+incompatible // indirect
	github.com/vishvananda/netlink v1.1.1-0.20201029203352-d40f9887b852
	github.com/xeipuuv/gojsonschema v1.2.0
	go.uber.org/goleak v1.1.10
	go.uber.org/zap v1.17.0
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2
	golang.org/x/net v0.0.0-20210805182204-aaa1db679c0d
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/tools v0.1.2
	google.golang.org/grpc v1.38.1
	google.golang.org/grpc/examples v0.0.0-20210630181457-52546c5d89b7
	google.golang.org/protobuf v1.26.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/nxadm/tail => github.com/lukedirtwalker/tail v1.3.1-0.20190919080739-7f7d37fab281

replace github.com/smartystreets/goconvey => github.com/kormat/goconvey v0.0.0-20191113114839-63cc4eee0dbc

go 1.14

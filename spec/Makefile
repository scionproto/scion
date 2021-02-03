.PHONY: all bundle_spec_files bundle_spec_files_swagger_cli gen_boilerplate_code
all: bundle_spec_files gen_boilerplate_code
GOPATH?=${HOME}/go
GOBIN?=${GOPATH}/bin

bundle_spec_files:
	docker build -t openapicli -f ./tools/openapicli_Dockerfile .
	docker run -v "$$PWD"/../:/scion --rm  openapicli openapi bundle --ext yml --output /scion/spec/control.gen.yml /scion/spec/control/spec.yml
	sed -i '1s;^;# GENERATED FILE DO NOT EDIT\n;' control.gen.yml
	docker image remove openapicli

bundle_spec_files_swagger_cli:
	docker build -t swagger-cli -f ./tools/swagger-cli_Dockerfile .
	docker run -v "$$PWD"/../:/scion --rm  jeanberu/swagger-cli swagger-cli bundle -t yaml -o /scion/spec/control.gen.yaml /scion/spec/control/spec.yml
	sed -i '1s;^;# GENERATED FILE DO NOT EDIT\n;' control.gen.yaml
	docker image remove swagger-cli

gen_boilerplate_code:
	# generate boilerplate code form specfile
	@${GOBIN}/oapi-codegen -package api -generate spec control.gen.yml > ../go/pkg/cs/api/spec.gen.go
	@${GOBIN}/oapi-codegen -package api -generate types control.gen.yml > ../go/pkg/cs/api/types.gen.go
	@${GOBIN}/oapi-codegen -package api -generate chi-server control.gen.yml > ../go/pkg/cs/api/server.gen.go
	go fmt ../go/pkg/cs/api/

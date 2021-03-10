.PHONY: all bundle_spec_files

all: bundle_spec_files

bundle_spec_files:
	docker build -t openapicli -f ./tools/openapicli_Dockerfile .
	docker run -v "$$PWD":/spec --rm  openapicli openapi bundle --ext yml --output /spec/control.gen.yml /spec/control/spec.yml
	sed -i '1s;^;# GENERATED FILE DO NOT EDIT\n;' control.gen.yml
	docker run -v "$$PWD":/spec --rm  openapicli openapi bundle --ext yml --output /spec/ca.gen.yml /spec/ca/spec.yml
	sed -i '1s;^;# GENERATED FILE DO NOT EDIT\n;' ca.gen.yml
	docker image remove openapicli

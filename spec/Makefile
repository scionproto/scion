.PHONY: all bundle_spec_files lint

all: bundle_spec_files

bundle_spec_files:
	bazel run @spec_npm//@redocly/openapi-cli/bin:openapi -- bundle --ext yml --output ${PWD}/spec/control.gen.yml ${PWD}/spec/control/spec.yml
	sed -i '1s;^;# GENERATED FILE DO NOT EDIT\n;' control.gen.yml
	bazel run @spec_npm//@redocly/openapi-cli/bin:openapi -- bundle --ext yml --output ${PWD}/spec/ca.gen.yml ${PWD}/spec/ca/spec.yml
	sed -i '1s;^;# GENERATED FILE DO NOT EDIT\n;' ca.gen.yml

lint:
	bazel run @spec_npm//@stoplight/spectral-cli/bin:spectral -- lint --ruleset ${PWD}/spec/.spectral.yml ${PWD}/spec/*.gen.yml

.PHONY: lint

all: lint

# TODO(lukedirtwalker): make this go away...
lint:
	bazel run --config=quiet @rules_openapi_npm//@stoplight/spectral-cli/bin:spectral -- lint --ruleset ${PWD}/spec/.spectral.yml ${PWD}/spec/*.gen.yml

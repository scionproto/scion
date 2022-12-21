.PHONY: lint

all: lint

# TODO(lukedirtwalker): make this go away...
lint:
	bazel run --ui_event_filters=-info,-stdout,-stderr --noshow_progress @rules_openapi_npm//@stoplight/spectral-cli/bin:spectral -- lint --ruleset ${PWD}/spec/.spectral.yml ${PWD}/spec/*.gen.yml

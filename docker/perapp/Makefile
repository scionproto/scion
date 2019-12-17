DOCKER_ARGS += --no-cache
ifndef DEBUG
DOCKER_ARGS += -q
endif

ALL_TARGETS = base apps debug
.PHONY: $(ALL_TARGETS)
all: $(ALL_TARGETS)
hashes/scion: ../_build/scion.stamp
	./docker_hash scion

.PHONY: clean
clean:
	@rm -f hashes/*; \
	for i in $(APP_TARGETS) $(BASE_TARGETS) $(DEBUG_TARGETS); do \
		./remove_image $$i latest; \
	done; \
	docker image prune -f

# Base images
BASE_TARGETS = app_builder
.PHONY: $(BASE_TARGETS)
base: $(BASE_TARGETS)

app_builder: hashes/app_builder
hashes/app_builder: base/Dockerfile.builder hashes/scion
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $< files/

# App images
APP_TARGETS = bazel
.PHONY: $(APP_TARGETS)
apps: $(APP_TARGETS)

bazel:
	./build-images.sh prod
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build hashes/sig app/Dockerfile.sig

# Debug images
DEBUG_TARGETS = bazel_debug
.PHONY: $(DEBUG_TARGETS)
debug: $(DEBUG_TARGETS)

bazel_debug:
	./build-images.sh debug
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build hashes/sig_debug debug/Dockerfile.sig

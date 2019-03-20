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
BASE_TARGETS = app_builder app_base python_base debug_base
.PHONY: $(BASE_TARGETS)
base: $(BASE_TARGETS)

app_builder: hashes/app_builder
hashes/app_builder: base/Dockerfile.builder hashes/scion
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $< files/

app_base: hashes/app_base
hashes/app_base: base/Dockerfile.base hashes/scion
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $< files/

python_base: hashes/python_base
hashes/python_base: base/Dockerfile.python hashes/app_base
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $< files/

debug_base: hashes/debug_base
hashes/debug_base: base/Dockerfile.debug hashes/scion
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $< files/

# App images
APP_TARGETS = bazel dispatcher path_py beacon_py cert_py sciond_py
.PHONY: $(APP_TARGETS)
apps: $(APP_TARGETS)

bazel: ../_build/scion.stamp
	./build-images.sh prod
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build hashes/sig app/Dockerfile.sig

dispatcher: hashes/dispatcher
hashes/dispatcher: app/Dockerfile.dispatcher hashes/app_base hashes/app_builder
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

path_py: hashes/path_py
hashes/path_py: app/Dockerfile.path_py hashes/python_base
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

beacon_py: hashes/beacon_py
hashes/beacon_py: app/Dockerfile.beacon_py hashes/python_base
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

cert_py: hashes/cert_py
hashes/cert_py: app/Dockerfile.cert_py hashes/python_base
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

sciond_py: hashes/sciond_py
hashes/sciond_py: app/Dockerfile.sciond_py hashes/python_base
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

# Debug images
DEBUG_TARGETS = bazel_debug dispatcher_debug path_py_debug beacon_py_debug cert_py_debug sciond_py_debug
.PHONY: $(DEBUG_TARGETS)
debug: $(DEBUG_TARGETS)

bazel_debug: ../_build/scion.stamp
	./build-images.sh debug
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build hashes/sig_debug app/Dockerfile.sig

border_debug:
	bazel run //go/border:debug
	docker tag scion/go/border:debug scion_border_debug:latest

dispatcher_debug: hashes/dispatcher_debug
hashes/dispatcher_debug: debug/Dockerfile.dispatcher hashes/debug_base hashes/dispatcher
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

dispatcher_go_debug:
	bazel run //go/godispatcher:debug
	docker tag scion/go/godispatcher:debug scion_dispatcher_go:latest

path_py_debug: hashes/path_py_debug
hashes/path_py_debug: debug/Dockerfile.path_py hashes/debug_base hashes/path_py
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

path_debug:
	bazel run //go/path_srv:debug
	docker tag scion/go/path_srv:debug scion_path_debug:latest

beacon_py_debug: hashes/beacon_py_debug
hashes/beacon_py_debug: debug/Dockerfile.beacon_py hashes/debug_base hashes/beacon_py
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

cert_py_debug: hashes/cert_py_debug
hashes/cert_py_debug: debug/Dockerfile.cert_py hashes/debug_base hashes/cert_py
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

cert_debug:
	bazel run //go/cert_srv:debug
	docker tag scion/go/cert_srv:debug scion_cert_debug:latest

sciond_py_debug: hashes/sciond_py_debug
hashes/sciond_py_debug: debug/Dockerfile.sciond_py hashes/debug_base hashes/sciond_py
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

sciond_debug:
	bazel run //go/sciond:debug
	docker tag scion/go/sciond:debug scion_sciond_debug:latest

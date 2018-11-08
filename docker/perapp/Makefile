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
APP_TARGETS = border dispatcher sig path_py path beacon_py cert_py sciond_py sciond
.PHONY: $(APP_TARGETS)
apps: $(APP_TARGETS)

border: hashes/border
hashes/border: app/Dockerfile.border hashes/app_base hashes/app_builder
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

dispatcher: hashes/dispatcher
hashes/dispatcher: app/Dockerfile.dispatcher hashes/app_base hashes/app_builder
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

sig: hashes/sig
hashes/sig: app/Dockerfile.sig hashes/app_base hashes/app_builder
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

path_py: hashes/path_py
hashes/path_py: app/Dockerfile.path_py hashes/python_base
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

path: hashes/path
hashes/path: app/Dockerfile.path hashes/app_base hashes/app_builder
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

sciond: hashes/sciond
hashes/sciond: app/Dockerfile.sciond hashes/app_base hashes/app_builder
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

# Debug images
DEBUG_TARGETS = border_debug dispatcher_debug sig_debug path_debug_py path_debug beacon_py_debug cert_py_debug sciond_py_debug sciond_debug
.PHONY: $(DEBUG_TARGETS)
debug: $(DEBUG_TARGETS)

border_debug: hashes/border_debug
hashes/border_debug: debug/Dockerfile.border hashes/debug_base hashes/border
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

dispatcher_debug: hashes/dispatcher_debug
hashes/dispatcher_debug: debug/Dockerfile.dispatcher hashes/debug_base hashes/dispatcher
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

sig_debug: hashes/sig_debug
hashes/sig_debug: debug/Dockerfile.sig hashes/debug_base hashes/sig
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

path_debug_py: hashes/path_debug_py
hashes/path_debug_py: debug/Dockerfile.path_py hashes/debug_base hashes/path_py
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

path_debug: hashes/path_debug
hashes/path_debug: app/Dockerfile.path hashes/debug_base hashes/path
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

beacon_py_debug: hashes/beacon_py_debug
hashes/beacon_py_debug: debug/Dockerfile.beacon_py hashes/debug_base hashes/beacon_py
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

cert_py_debug: hashes/cert_py_debug
hashes/cert_py_debug: debug/Dockerfile.cert_py hashes/debug_base hashes/cert_py
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

sciond_py_debug: hashes/sciond_py_debug
hashes/sciond_py_debug: debug/Dockerfile.sciond_py hashes/debug_base hashes/sciond_py
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

sciond_debug: hashes/sciond_debug
hashes/sciond_debug: app/Dockerfile.sciond hashes/debug_base hashes/sciond
	DOCKER_ARGS="$(DOCKER_ARGS)" ./docker_build $@ $<

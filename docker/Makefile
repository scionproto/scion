.PHONY: clean apps debug prod test

apps: prod test

BAZEL_PROJECT?=scion

distroless_parser:
	echo $(PWD)
	bazel build @distroless//package_manager:dpkg_parser.par
	mkdir -p ../bazel-$(BAZEL_PROJECT)/external/distroless/bazel-bin
	ln -sf $(PWD)/bazel-bin/external/distroless/package_manager\
		../bazel-$(BAZEL_PROJECT)/external/distroless/bazel-bin/package_manager

debug: distroless_parser
	bazel run -c dbg //docker:debug
	docker image build -t "scion_sig_debug:latest" -f dockerfiles/sig.debug .
	docker image remove scion_sig_nocap_debug

prod: distroless_parser
	bazel run -c opt //docker:prod
	docker image build -t "scion_sig:latest" -f dockerfiles/sig.prod .
	docker image remove scion_sig_nocap

test: distroless_parser
	bazel run //docker:test
	docker build -t "scion_sig_acceptance:latest" -f dockerfiles/sig_accept .
	docker image remove scion_sig_acceptance_nocap scionproto/docker-caps

clean:
	docker image ls --filter reference=scion* -q | xargs docker image rm

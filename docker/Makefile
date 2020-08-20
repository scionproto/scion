.PHONY: clean apps debug prod test

apps: prod test

debug:
	bazel run -c dbg //docker:debug

prod:
	bazel run -c opt //docker:prod

test:
	bazel run //docker:test

clean:
	docker image ls --filter reference=scion* -q | xargs docker image rm

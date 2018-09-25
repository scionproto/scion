#!/bin/bash

# On a SCION topology where end to end connectivity is available, after
# restarting the dispatcher and flushing SCIOND path databases, end to end
# connectivity should still be available.

TEST_NAME="reconnecting"
TEST_TOPOLOGY="topology/Tiny.topo"

test_setup() {
	set -e
	./scion.sh topology -c $TEST_TOPOLOGY -d -sd=go -ps=go
	# Enable automatic dispatcher reconnects in SCIOND and PS
	for sd in gen/ISD1/*/endhost/sciond.toml; do
		sed -i '/\[general\]/a ReconnectToDispatcher = true' "$sd"
	done
	for ps in gen/ISD1/*/ps*/psconfig.toml; do
		sed -i '/\[general\]/a ReconnectToDispatcher = true' "$ps"
	done
	./scion.sh run
}

test_run() {
	set -e
	python/integration/end2end_test.py 1-ff00:0:112 1-ff00:0:110
	docker restart dispatcher
	sqlite3 gen-cache/sd1-ff00_0_112.path.db "delete from segments;"
	python/integration/end2end_test.py 1-ff00:0:112 1-ff00:0:110
}

test_teardown() {
	set -e
	./scion.sh stop
}

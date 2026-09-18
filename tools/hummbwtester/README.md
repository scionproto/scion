# Hummingbird bandwidth tester

`hummbwtester` is a continuous-traffic experiment for comparing Hummingbird-reserved SCION traffic with ordinary best-effort SCION traffic.
It runs one UDP server and any number of clients inside the Docker test topology.
Clients send paced payload traffic and periodic probes;
replies report remote receive, loss, and ordering information back to the client.

The experiment is intentionally client-observed: the server does not expose Prometheus metrics.
Each client exposes its own metrics endpoint,
including the server observations returned in probe replies.

## How it works

The experiment uses the generated Docker topology in `gen/`; it never generates a topology itself. `tools/hummbwtester/setup-topology.py` reads the generated Docker Compose file and topology files, then:

- configures every generated border router with the experiment's ingress and egress sizing;
- starts the existing Docker topology;
- discovers the border-router interfaces joining different ASes;
- applies a TBF qdisc inside every BR network namespace using the configured `tc` values;
- copies the statically linked `hummbwtester` artifact built by `make build-dev` to every configured tester container; and
- generates Prometheus file-service-discovery targets in `gen/hummbwtester-prometheus/`.

The cap is applied in both directions of each selected inter-AS link, before packets leave each
border router's network namespace.
In tiny topology this shapes the `110 <-> 111` and `110 <-> 112` links,
while leaving the intra-AS bridges unshaped.

`tools/hummbwtester/run-humm-bwtester-local.py` starts the Docker-topology server,
waits two seconds, and starts all clients concurrently.
Hummingbird clients either derive reservations from `/share/gen` master keys or buy them from the
marketplace advertised by the selected SCION path, according to the global `hummingbird` setting.
Marketplace runs log in through the registration website configured in the workload JSON and pass
the resulting JWT to client processes through an owner-only file.
Key-derived Hummingbird clients choose a random nonzero 22-bit reservation ID when they start and
reuse it across reservation renewals. Marketplace reservations use the IDs returned by the
marketplace. Client workload and reservation settings are read from the JSON configuration.

## Configuration

Edit [hummbwtester.json](hummbwtester.json). It has six required top-level sections:

- `server`: the server's `isd_as`, tester `host`, UDP `port`, and
  `receive_buffer_size`.
- `hummingbird_clients`: zero or more Hummingbird client endpoint objects.
- `best_effort_clients`: zero or more best-effort client endpoint objects.
- `router`: experiment-only socket and queue settings written to every generated BR TOML before
  startup: `send_buffer_size`, `receive_buffer_size`, `ingress_batch_size`, `processor_queue_size`,
  `egress_batch_size`, and `egress_queue_size`.
- `tc`: TBF `rate`, `burst`, and explicit queue `limit` values passed to `tc`.
- `hummingbird`: required global reservation source (`keys` or `marketplace`). Marketplace mode also
  requires a `marketplace` object with `url`, `username`, and `password_env`; `sub_account` is
  optional. The password is read from the named environment variable, never from JSON. The Docker
  runner discovers the reachable registration URL from `gen/`; `url` is used by SSH runs.

Linux doubles the requested `SO_SNDBUF` and `SO_RCVBUF` internally. The sample requests a 16 KiB
send buffer and uses a deliberately larger 256 KiB TBF limit, so socket-memory backpressure should
stop the BR writer before TBF tail-drop. It requests the host's current 4 MiB maximum receive
buffer for every BR socket and for the tester server. If these receive queues still overflow,
increase `net.core.rmem_max` and both configured receive-buffer values together. Its ingress batch
of 64 avoids the receive-side cost of one-packet batches; it is not queue storage. Each fast- and
slow-path processor ingress queue and each priority/best-effort egress queue has 640 slots to absorb
short scheduling stalls.

Every client requires these fields:

- `client_id`: a unique identifier used as the sole custom Prometheus label.
- `isd_as`, `host`, and `port`: the tester-container endpoint. Use port `0` for an ephemeral UDP port.
- `bandwidth`: payload send rate passed as `-bandwidth`, such as `"1Mbps"`.
- `maxburst`: maximum payload rate while repaying pacing debt, passed as `-maxburst`. It must be
  greater than or equal to `bandwidth`.
- `duration`: test length passed as `-duration`, such as `"600s"`.

Hummingbird clients additionally require `hummingbird_reservation`, an object with:

- `bandwidth`: in `keys` mode, a forward reservation bandwidth class (integer); in `marketplace`
  mode, a unit-bearing bandwidth such as `"100kbps"`, `"1mbps"`, or `"1gbps"`.
- `duration`: reservation duration, such as `"1m"`.
- `reverse_bandwidth`: reverse reservation bandwidth in the same representation; use `0` in keys
  mode or `"0kbps"` in marketplace mode for no reverse reservation.
- `renewal_ahead` (optional): how long before expiry to request the next reservation; defaults to
  `"20s"`.
- `reservation_overlap` (optional): how long before expiry to switch to the next reservation;
  defaults to `"15s"`.
- `humm_start_offset` (optional): a signed offset added to the calculated reservation start time;
  defaults to `"-1s"`. For example, `"-3s"` starts the reservation three seconds earlier.

Both client types may optionally set `payload_size` and `pong_rate`. They are passed as
`-payload-size` and `-pong-rate`. The Hummingbird reservation timing fields are passed as
`-renewal-ahead`, `-reservation-overlap`, and `-humm-start-offset`; omitted fields use the binary's
built-in defaults. `reservation_overlap` must not exceed `renewal_ahead`, ensuring the replacement
has been requested before its handover. With a negative start offset, the replacement's validity
window begins before handover and overlaps the old window by the overlap plus the magnitude of that
offset. After handover, the old reservation remains valid for the configured overlap while its
packets drain.

### Bounded catch-up after a missed deadline

Payload packets and pong requests have independent schedules. The client wakes every millisecond
and compares the bytes sent with an absolute `bandwidth` schedule. It sends the packets due at that
instant back-to-back, preserving fractional byte credit between wakes so packetization does not
change the long-term rate. Every packet is encoded and passed separately to `WriteTo`, giving it a
fresh sequence number, timestamp, and (for Hummingbird) dataplane MAC.

A small token bucket bounds each catch-up batch and replenishes at `maxburst`. Scheduler or CPU
delays therefore create retained debt rather than an unbounded burst; while debt exists, the client
catches up at no more than `maxburst`, then resumes `bandwidth`.

For example, a 10 Mbps client with `maxburst` 20 Mbps that accumulates 10 megabits of debt has
10 Mbps of extra catch-up capacity and needs at least one second to repay it. Setting `maxburst`
equal to `bandwidth` retains the debt accounting but provides no acceleration, so it cannot catch
up while continuously sending.

Pong probes do not contribute to the configured payload bandwidth and retain their independent
no-catch-up schedule. A pacing tick that leaves its schedule behind contributes to the rate-limited
`Pacing schedule behind` log message. A request that exceeds its RTT deadline increments
`hummbwtester_client_pong_lost_total`, but a later reply is still accepted for latency and remote
receive/loss statistics. Such replies also increment
`hummbwtester_client_pong_late_replies_received_total`. Replies are discarded as stale if either
their sequence number or echoed client send timestamp does not advance beyond the last accepted
reply.

For example, this commented dummy Hummingbird client shows every supported client field:

```jsonc
// {
//   "client_id": "hummingbird-tuned-example",
//   "isd_as": "1-ff00:0:111",
//   "host": "172.20.0.29",
//   "port": 0,
//   "bandwidth": "2Mbps",
//   "maxburst": "4Mbps",
//   "duration": "5m",
//   "hummingbird_reservation": {
//     "bandwidth": "1mbps",
//     "duration": "1m",
//     "reverse_bandwidth": "1mbps",
//     "renewal_ahead": "20s",
//     "reservation_overlap": "15s",
//     "humm_start_offset": "-1s"
//   },
//   "payload_size": 1200,
//   "pong_rate": 2.0
// }
```

Client IDs must be unique and match `[A-Za-z0-9._-]+`.

Daemon connectors are deliberately not configured:
they are derived from `gen/sciond_addresses.json` for the configured AS.
Metrics ports are also derived:
after sorting all clients lexicographically by `client_id`,
the first receives `9090`, the next `9091`, and so on.
Prometheus adds `client_id` as the sole custom label to that client's metrics.

The endpoint addresses must match the generated tester-container addresses.
For Docker tiny, the sample configuration places the server in AS112 and both sample clients in AS111.

While clients run, the runner prints one timestamped table per minute. Counter rows are changes
since the preceding report and TBF backlog is the current number of queued bytes. Columns identify
external border-router interfaces. The table reports BFD sent, received, and inferred lost packets
(peer sent minus local received); total Hummingbird demotions; `busy_forwarder` drops; and TBF
drops, overlimits, and backlog.

These values are observation-only: BFD state changes, packet drops, TBF counters, and log entries
never stop or fail an experiment. Only an experiment client or server process exiting unsuccessfully
causes the runner to return a failure.

## First run

From the repository root, build the Docker images and generate Docker tiny topology once:

```bash
make build-dev
make docker-images
./scion.sh topology -d -c topology/tiny.topo -m 1-ff00:0:111
```

Review and edit `tools/hummbwtester/hummbwtester.json`, then prepare the experiment:

```bash
./tools/hummbwtester/setup-topology.py
```

Setup prints the derived metrics-port mapping, starts the topology,
applies the qdiscs, and copies the binary built by `make build-dev`.
Start the experiment with:

```bash
./tools/hummbwtester/run-humm-bwtester-local.py
```

Logs are written beneath `logs/hummbwtester/`, one file per `client_id` plus `server.log`.

## SSH real-topology runs

For SSH-accessible SCION hosts, copy [ssh-inventory.json.example](ssh-inventory.json.example) to
`ssh-inventory.json` and configure it. List only dedicated interfaces that may be shaped.
SSH aliases may use `ProxyJump`; the runner uses them unchanged.

Set the password named by `hummingbird.marketplace.password_env`, build the artifact, then run:

```bash
make build-dev
./tools/hummbwtester/run-humm-bwtester-ssh.py \
  --config tools/hummbwtester/hummbwtester.json \
  --inventory tools/hummbwtester/ssh-inventory.json
```

The controller verifies and uploads the built binary,
obtains the configured user's JWT from `hummingbird.marketplace.url`,
and uploads it to an owner-only per-run remote file.
The SSH launch shell reads that file only immediately before `exec`;
it is never placed in command arguments or the inventory.
The runner creates SSH metric tunnels and Prometheus file-SD targets under `gen/hummbwtester-prometheus/`,
removes remote PID/JWT files on exit, and removes a `tc`-set TBF only when
the inventory explicitly declares a `noqueue` dedicated-link interface.

## Regular run cycle

For a configuration change, run setup again before running the experiment:

```bash
./tools/hummbwtester/setup-topology.py
./tools/hummbwtester/run-humm-bwtester-local.py
```

For a tester source change, first rebuild the standard development artifacts, then run setup:

```bash
make build-dev
./tools/hummbwtester/setup-topology.py
./tools/hummbwtester/run-humm-bwtester-local.py
```

For a router source change, rebuild and reload the Docker images as well before setup:

```bash
make build-dev
make docker-images
./tools/hummbwtester/setup-topology.py
./tools/hummbwtester/run-humm-bwtester-local.py
```

After `./scion.sh stop`, Docker removes the bridges and their qdiscs.
Do not use `./scion.sh start` alone for another experiment;
rerun `./tools/hummbwtester/setup-topology.py` so it starts the existing generated topology,
recreates the bandwidth caps, and recopies the binary.

`tools/hummbwtester/setup-topology.py` requires an existing `gen/scion-dc.yml`.
If `gen/` was generated for supervisord instead,
regenerate Docker topology with the command in the first-run section.

## Monitoring

The optional Prometheus/Grafana stack is in [monitoring](monitoring/README.md).
After setup has generated targets, start it with:

```bash
cd tools/hummbwtester/monitoring
docker compose up -d
```

Prometheus is available at `http://localhost:8090`;
Grafana is at `http://localhost:3000` (`admin` / `admin`).
The dashboard groups client series by `client_id`.

## Tests

Run the focused Go and orchestration tests from the repository root:

```bash
go test ./tools/hummbwtester
bazel test //tools/hummbwtester:go_default_test //tools/hummbwtester:orchestration_test \\
  //tools/hummbwtester:ssh_orchestration_test
```

Run the no-sleep client send-path benchmark with:

```bash
go test ./tools/hummbwtester -run '^$' -bench '^BenchmarkSerializeWriteTo$' -benchmem
```

The Python test covers configuration validation, deterministic metrics-port assignment, and
per-minute report aggregation.
The Go test covers random Hummingbird reservation-ID generation.
A practical Docker smoke test is to run setup, stop SCION, and rerun setup. The generated
`hummbwtester_tc_*` helpers inspect qdiscs inside the BR network namespaces.

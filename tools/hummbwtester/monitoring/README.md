# hummbwtester monitoring

This directory contains a small Docker Compose setup for observing the Prometheus metrics
exported by `./tools/hummbwtester`.

It follows the same basic pattern as `./monitoring-prometheus-grafana/topology`: a local
Prometheus instance scrapes metrics from the running SCION tooling, and Grafana is provided for
interactive dashboards. For `hummbwtester`, the scrape targets are taken from
`tools/hummbwtester/hummbwtester.json` and `tools/hummbwtester/run-humm-bwtester-local.py`:

- client metrics, including observations reported by the server: ports derived from sorted
  `client_id` values, beginning at `9090`

Prometheus also scrapes the border router metrics from the tiny topology, using the same BR
targets as `./monitoring-prometheus-grafana/topology/prometheus.yml`.

Prometheus runs in Docker with host networking so it can reach the Docker tester endpoints. The
setup script generates its file-based client and BR targets under `gen/`.

## Files

- `docker-compose.yml`: starts Prometheus and Grafana
- `prometheus.yml`: scrape configuration for the `hummbwtester` client and border routers
- `grafana/provisioning`: auto-configures the Prometheus data source and dashboard loading
- `grafana/dashboards/hummbwtester-overview.json`: starter Grafana dashboard for traffic,
  remote receive bandwidth, latency, jitter, reservation lifetime, border router flyovers, and
  loss signals

## Configuration

`tools/hummbwtester/hummbwtester.json` contains the server, Hummingbird clients, best-effort clients, and TBF
settings. Client SCION daemon addresses are read from `gen/sciond_addresses.json`. Client metrics
ports are assigned after sorting all client IDs: `9090`, `9091`, and so on. Prometheus attaches
the configured `client_id` as the sole custom label on each client target.

## Start

1. Set up the existing Docker topology from the repository root:

   ```bash
   ./tools/hummbwtester/setup-topology.py
   ./tools/hummbwtester/run-humm-bwtester-local.py
   ```

2. In another terminal, start the monitoring stack:

   ```bash
   cd tools/hummbwtester/monitoring
   docker compose up -d
   ```

3. Check that the containers are running:

   ```bash
   docker compose ps
   ```

## Stop

Stop the monitoring stack from this directory:

```bash
docker compose down
```

If you also want to remove the persisted Prometheus and Grafana data volumes:

```bash
docker compose down -v
```

`./run-humm-bwtester.sh` stops independently from the monitoring stack, so you can interrupt it
without shutting down Prometheus or Grafana.

## Use

Prometheus is exposed on [http://localhost:8090](http://localhost:8090). The Prometheus UI is
mapped to `8090` instead of the Prometheus default port `9090`.

Grafana is exposed on [http://localhost:3000](http://localhost:3000). The default login is
`admin` / `admin`.

If either host port is already in use, override it when starting Compose:

```bash
PROMETHEUS_PORT=18090 GRAFANA_PORT=13000 docker compose up -d
```

You can also put those variables in a local `.env` file in this directory if you want the same
port selection on every run.

## Viewing metrics

### In Prometheus

Open `http://localhost:${PROMETHEUS_PORT:-8090}/targets` and confirm that
`hummbwtester-client` and `scion-border-routers` are `UP`.

Then use the expression browser at `http://localhost:${PROMETHEUS_PORT:-8090}/graph`.
Useful example queries include:

- `hummbwtester_client_send_rate_bps`
- `hummbwtester_client_jitter_seconds`
- `hummbwtester_client_pong_late_replies_received_total`
- `hummbwtester_client_market_roundtrip_last_seconds`
- `hummbwtester_client_market_roundtrips_total`
- `histogram_quantile(0.95, sum by (le) (rate(hummbwtester_client_rtt_seconds_bucket[1m])))`
- `hummbwtester_client_remote_receive_rate_bps`
- `hummbwtester_client_remote_stats_age_seconds`
- `router_humm_flyover_pkts_total`
- `router_priority_forwarded_pkts_total`
- `router_processed_pkts_total`
- `router_bfd_sent_packets_total`
- `router_bfd_received_packets_total`
- `router_humm_demoted_freshness_total`
- `router_humm_demoted_expired_total`
- `router_humm_demoted_tokenbucket_total`
- `router_queue_depth`
- `router_queue_depth_high_watermark`
- `router_underlay_receive_overflow_pkts_total`
- `process_running_seconds_total`
- `process_runnable_seconds_total`
- `go_sched_maxprocs_threads`

### In Grafana

Open `http://localhost:${GRAFANA_PORT:-3000}` and log in with `admin` / `admin`.

The Prometheus data source is provisioned automatically, and the dashboard
`hummbwtester Overview` is loaded automatically in the `hummbwtester` folder.

That dashboard includes:

- traffic receive rates and send-minus-receive gaps, split by Hummingbird and best-effort client
- p95 RTT and jitter panels
- client reservation success rate
- packet rate insights with priority and best-effort packet rates
- border router egress queue depths for priority and best-effort queues
- total border router demotion rates by freshness, expiry, and token bucket cause
- detailed demotion rates by cause, border router, and interface
- border-router running and scheduler-denied CPU time
- total and per-socket Linux UDP receive-queue overflows for the border routers
- aggregate BFD packet-loss and state-change counts per minute, plus current per-interface counters
- pong request-to-reply gaps for remote-sent and client-received replies

If you want to build your own panels, create a new dashboard in Grafana and query the same
metrics that appear in `./tools/hummbwtester/metrics.go`.

Linux delivers `SO_RXQ_OVFL` as ancillary data on a packet received after an overflow. Therefore,
`router_underlay_receive_overflow_pkts_total` can update slightly after the actual drop. Its
`local` and `remote` labels identify the socket; `remote="unconnected"` denotes a BR internal
socket. The metric cannot carry an interface or priority label because the kernel drops the
datagram before the BR receives and classifies it.

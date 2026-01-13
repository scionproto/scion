# SCION Router Performance Monitoring

> **WARNING**: This monitoring stack is for LOCAL DEVELOPMENT ONLY.
> Do not expose ports 9090 or 3000 to the internet.

## Quick Start

```bash
# Start SCION tutorial with monitoring
docker compose --profile monitoring up -d

# Generate some traffic
docker exec scion04 scion ping 15-ffaa:1:1,127.0.0.1 -c 1000 --interval 10ms

# Open Grafana
open http://localhost:3000/d/scion-router-processing
```

## Port Reference

| Port | Service | Purpose |
|------|---------|---------|
| 9100 | Router (internal) | Prometheus metrics endpoint |
| 9090 | Prometheus | Query UI and API |
| 3000 | Grafana | Dashboards (login: admin/admin) |

---

## Creating Your Own Performance Dashboard

This section explains how to add metrics and dashboards to investigate your own
performance hypotheses. The pattern established here can be applied to any
SCION component.

### The Hypothesis-Driven Approach

Every good performance dashboard answers **ONE specific question**:

| Dashboard | Question |
|-----------|----------|
| `router-processing.json` | "Is MAC verification the bottleneck?" |
| (your dashboard) | "Is path lookup slow under load?" |
| (your dashboard) | "Does BFD overhead matter at scale?" |

**Don't** create dashboards that "show everything". Create dashboards that
**answer questions**.

### Step 1: Form Your Hypothesis

Before writing any code, write down:

1. **The question**: "Is X the bottleneck?" or "Does Y scale linearly?"
2. **How you'll know**: "If X is >30% of total time, then yes"
3. **What you'll do**: "If yes, investigate caching. If no, look elsewhere."

Example from this PR:
- Question: Is MAC verification the bottleneck?
- Signal: MAC verify time as % of total processing time
- Threshold: >30% = worth optimizing, <10% = look elsewhere

### Step 2: Add Metrics (Go Code)

#### Metric Naming Convention

```
router_<component>_<measurement>_<unit>
```

Examples:
- `router_process_duration_seconds` - time spent processing
- `router_cache_hit_total` - cache hits (counter)
- `router_queue_depth` - current queue size (gauge)

#### Adding a Histogram (for latency)

In `router/metrics.go`:

```go
// 1. Add to Metrics struct
type Metrics struct {
    // ... existing fields
    YourMetric *prometheus.HistogramVec
}

// 2. Initialize in NewMetrics()
YourMetric: promauto.NewHistogramVec(
    prometheus.HistogramOpts{
        Name:    "router_your_component_duration_seconds",
        Help:    "Time spent in your component",
        // Buckets for microsecond-level operations:
        Buckets: []float64{.000001, .000005, .00001, .00005, .0001, .0005, .001, .005, .01},
    },
    []string{"label1", "label2"},
),
```

#### Instrumenting Code

In `router/dataplane.go` (or relevant file):

```go
func (p *processor) yourFunction() error {
    start := time.Now()
    defer func() {
        p.d.Metrics.YourMetric.WithLabelValues("value1", "value2").Observe(
            time.Since(start).Seconds(),
        )
    }()

    // ... existing code unchanged
}
```

### Step 3: Document Your Metric

Add to `doc/manuals/router/metrics.rst`:

```rst
Your component duration
-----------------------

**Name**: ``router_your_component_duration_seconds``

**Type**: Histogram

**Description**: What this measures and why it matters.

**Labels**: ``label1``, ``label2``

**Buckets**: 1µs, 5µs, 10µs, 50µs, 100µs, 500µs, 1ms, 5ms, 10ms
```

### Step 4: Create Your Dashboard

Copy the template and modify:

```bash
cp provisioning/dashboards/TEMPLATE.json provisioning/dashboards/your-hypothesis.json
```

Key panels to include:

1. **The Answer Panel** - A single stat showing your key metric
   - Use thresholds: green (no problem), yellow (investigate), red (bottleneck)

2. **Time Series** - How does it change over time/load?

3. **Breakdown** - If labeled, show distribution across labels

4. **Context** - Related metrics that help interpret the answer

### Step 5: Test Your Hypothesis

```bash
# Rebuild router with new metrics
go build ./router/...

# Deploy to containers
docker cp bin/router scion01:/usr/bin/scion-router
docker restart scion01

# Generate load
for i in $(seq 1 20); do
  docker exec scion04 scion ping 15-ffaa:1:1,127.0.0.1 -c 500 --interval 5ms &
done
wait

# Check your dashboard
open http://localhost:3000/d/your-hypothesis
```

---

## Dashboard Template

See `provisioning/dashboards/TEMPLATE.json` for a starting point.

The template includes:
- Title row with your hypothesis question
- Key answer stat panel with thresholds
- Time series panel
- Placeholder for breakdown panels

---

## Contributing Dashboards

When contributing a new dashboard:

1. **Name it after the question**: `router-mac-bottleneck.json`, not `router-metrics.json`
2. **Include the hypothesis in the description**
3. **Set meaningful thresholds** that indicate when action is needed
4. **Test with realistic load** before submitting

---

## Useful PromQL Patterns

### Latency percentiles
```promql
histogram_quantile(0.99, rate(router_your_metric_bucket[1m]))
```

### Percentage of total
```promql
sum(rate(metric_a[5m])) / sum(rate(metric_total[5m]))
```

### Rate of change
```promql
rate(router_counter_total[1m])
```

### Compare before/after
```promql
# Use time shift
rate(metric[5m]) / rate(metric[5m] offset 1h)
```

# Metrics

Metrics definition and interactions should be consistent throughout the code
base. A common pattern makes it easier for developers to implement and refactor
metrics, and for operators to understand where metrics are coming from. As a
bonus, we should leverage the type system to help us spot as many errors as
possible.

## Placement

Metrics are defined in packages called metrics. For services we suggest moving
putting them to `go/svc_name/internal/metrics`. In `go/lib`, metrics should be
defined as internal sub-package of the lowest common ancestor of all packages
that intend to use the metrics.

Example file tree:

```bash
go
├── beacon_srv
│   └── internal
│       ├── metrics
│       │    ├── keepalive.go
│       │    ├── metrics.go
│       │    ├── originator.go
│       │    ├── propagator.go
│       │    └── registrar.go
│       ├── keepalive
│       │    ├── handler.go
│       │    └── sender.go
│       └── beaconing
│            ├── originator.go
│            ├── propagator.go
│            └── registrar.go
├── lib
│   └── pathdb
│       └── internal
│            └── metrics
```

General definitions are defined in `go/lib/prom` (e.g. commonly used result
label values).

## Definition

Metrics for each component are kept in a separate file (see `beaconing` above),
or, if they contain metrics for a single component in the `metrics.go` file. The
`metrics.go` file contains shared definitions (label and result values) and
metrics initialization. Everything else is put in the respective file. Metrics
initialization is done by assigning to a package variable (example below).

Commonly shared information goes to `lib/prom`:

```go
// lib/prom/metrics.go

// common result values
const (
    Success          = "success"
    ErrInternal      = "err_internal"
    ErrProcess       = "err_process"
    ErrNotClassified = "err_not_classified"
    ErrTimeout       = "err_timeout"
)

// common label names
const (
    LabelResult = "result"
    LabelStatus = "status"
    LabelSrc    = "src"
)
```

Example metrics for the beacon server:

```go
// beacon_srv/internal/metrics/metrics.go

import "github.com/scionproto/scion/go/lib/prom"

// Namespace is the metrics namespace for the beacon server.
const Namespace = "bs"

// Metrics initialization.
var (
    Keepalive  = newKeepalive()
    Propagator = newPropagator()
    Originator = newOriginator()
)

// Group label values in constant blocks.
// Mirror prom label values to have a consistent way
// of invoking in the client code.
const (
    Success          = prom.Success
    ErrProcess       = prom.ErrProcess
    ErrTimeout       = prom.ErrTimeout
    ErrInternal      = prom.ErrInternal
    ErrNotClassified = prom.ErrNotClassified
    ErrSpecial       = "err_special"
    ...
)

```

Each component is mapped to a single metrics struct. The struct exposes methods
to interact with the metrics. Labels are provided as a struct. This allows
reasonable static checking at compile time. Label structs should have the suffix
`Labels`. Label structs can be shared between components if they contain the
same label set.

An example metric struct:

```go
// beacon_srv/internal/metrics/originator.go

// OriginatorLabels define the labels attached to originator metrics.
type OriginatorLabels struct {
    EgIfID common.IFIDType
    Result string
}

// Labels returns the list of labels.
func (l OriginatorLabels) Labels() []string{
    return []string{"eg_ifid", prom.LabelResult}
}

// Values returns the label values in the order defined by Labels.
func (l OriginatorLabels) Values() []string {
    return []string{l.EgIfID.String(), l.Result}
}

type originator struct {
    beacons *prometheus.CounterVec
    duration    prometheus.Counter
}

func newOriginator() originator {
    sub := "originator"
    return originator{
        beacons: prom.NewCounterVec(Namespace, sub, "beacons_total",
            "Total number of beacons originated.", OriginatorLabels.Labels()),
        duration: prom.NewCounter(Namespace, sub, "duration_seconds_total",
            "Total time spent originating"),
    }
}

// Beacons returns the counter for the given label set.
func (o *originator) Beacons(l OriginatorLabels) prometheus.Counter {
    return o.beacons.WithLabelValues(l.Values()...)
}

// Duration returns the duration counter.
func (o *originator) Duration() prometheus.Counter {
    return o.duration
}
```

```go
// beacon_srv/internal/metrics/keepalive.go

// KeepaliveLabels define the labels attached to keepalive metrics.
type KeepaliveLabels struct {
    IfID   common.IFIDType
    Result string
}

// Labels returns the name of the labels in correct order.
func (l KeepaliveLabels) Labels() []string {
    return []string{"ifid", prom.LabelResult}
}

// Values returns the values of the label in correct order.
func (l KeepaliveLabels) Values() []string {
    return []string{l.IfID.String(), l.Result}
}

type keepalive struct {
    out prometheus.CounterVec
    in prometheus.CounterVec
}

func newKeepalive() keepalive {...}

// Transmits returns transmit counter.
func (k *keepalive) Transmits(l KeepaliveLabels) prometheus.Counter {
    return k.out.WithLabelValues(l.Values()...)
}

// Receives returns the receive counter.
func (k *keepalive) Receives(l KeepaliveLabels) prometheus.Counter {
    return k.in.WithLabelValues(l.Values()...)
}

```

Another example:

```go
// border/metrics/input.go

// SocketLabels defines a socket label set.
type SocketLabels struct {
    Socket string
}

// Labels returns the list of labels.
func (l SocketLabels) Labels() []string {
    return []string{"socket"}
}

// Values returns the label values in the order defined by Labels.
func (l SocketLabels) Values() []string {
    return []string{l.Socket}
}

type input struct {
    pkts    *prometheus.CounterVec
    bytes   *prometheus.CounterVec
    pktSize *prometheus.HistogramVec
}

func newInput() input {...}

// Pkts returns the counter for the given label set.
func (in *input) Pkts(l SocketLabels) prometheus.Counter {
    return in.pkts.WithLabelValues(l.Values()...)
}

// Bytes returns the counter for the given label set.
func (in *input) Bytes(l SocketLabels) prometheus.Counter {
    return in.bytes.WithLabelValues(l.Values()...)
}

// PktSize returns the counter for the given label set.
func (in *input) PktSize(l SocketLabels) prometheus.Counter {
    return in.pktSize.WithLabelValues(l.Values()...)
}
```

The imports into metrics should be kept to a minimum, to avoid circular imports.
We suggest that we restrict to `go/lib/prom` and `go/lib/common` for now.

## Usage

Regular case:

```go
// beacon_srv/internal/keepalive/sender.go

import "github.com/scionproto/scion/go/beacon_srv/internal/metrics"

func (s *Sender) Run(ctx context.Context) {
    ...
    for ifid, intf := range topo.IFInfoMap {
        l := metrics.KeepaliveLabel{IfID: ifid, Result: metrics.ErrNotClassified}
        if err := s.Send(msg, ov); err != nil {
            logger.Error("[keepalive.Sender] Unable to send packet", "err", err)
            l.Result = metrics.ErrProcess
            metrics.Keepalive.Transmit(l).Inc()
            continue
        }
        sentIfids = append(sentIfids, ifid)
        l.Result = metrics.Success
        metrics.Keepalive.Transmit(l).Inc()
    }
    ...
}
```

High-performance case:

```go
// border/io.go

import "github.com/scionproto/scion/go/border/metrics"


func (r *Router) posixInput(s *rctx.Sock, stop, stopped chan struct{}) {
    sock := s.Labels["sock"]

    // Pre-calculate metrics
    inputPkts := metrics.Input.PktsWith(sock)
    ...
Top:
    for {
        ...
        inputPkts.Add(float64(pktsRead))
        ...
    }
}
```

## Best Practices

1. [prometheus.io/docs/practices/naming/](https://prometheus.io/docs/practices/naming/)
1. Namespace should be one word
1. Subsystem should be one word (if present)
1. Use values that can be searched with regex. E.g. prepend `err_` for every error result.
1. `snake_case` label names and values
1. Put shared label names and values into `go/lib/prom`

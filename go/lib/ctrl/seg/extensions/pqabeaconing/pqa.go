package pqa_extension

import (
	"math"
)

// Global N paramter, determining no. of beacons seeked per target
const N = 1

// Represents an optimization direction, such as forward or backward
type Direction int

const (
	Forward = iota
	Backward
	Symmetric
)

func (d Direction) String() string {
	switch d {
	case Forward:
		return "Forward"
	case Backward:
		return "Backward"
	case Symmetric:
		return "Symmetric"
	default:
		return "Zero"
	}
}

// Represents a path quality to optimize for, such as latency
type Quality int

const (
	Latency = iota
	Throughput
)

func (q Quality) String() string {
	switch q {
	case Latency:
		return "Latency"
	case Throughput:
		return "Throughput"
	default:
		return "Unknown"
	}
}

// Optimality types: Functions returning the "better" value of the two
var optimFuncs = map[Quality]func(float64, float64) float64{
	Latency:    math.Max,
	Throughput: math.Min,
}

// Less(l, r) return true if l is strictly worse than r. Used for sorting.
func (q Quality) Less(l float64, r float64) bool {
	return optimFuncs[q](l, r) != l
}

// Map qualities to thei infimum values, i.e. values worse or equal than all possible values
var infValues = map[Quality]float64{
	Latency:    math.Inf(1),
	Throughput: math.Inf(-1),
}

// Returns the infimum value of a quality metric
func (q Quality) Infimum() float64 {
	return infValues[q]
}

// Tolerance for metrics of a path to be considered "symmetric"
// A path with forward metric fwd and backward metric bwd is considered
// symmetric if abs(fwd - bwd) <= symTol * max(abs(fwd), abs(bwd))
var symTols = map[Quality]float64{
	Latency:    0.1,
	Throughput: 0.1,
}

// Returns true if a path with forward metric a  and backward metric b should
// be considered symmetric in that metric. Commutative.
func (q Quality) AreSymmetric(a float64, b float64) bool {
	return math.Abs(a-b) <= symTols[q]*math.Max(math.Abs(a), math.Abs(b))
}

// Map qualities to functions combining metrics of two path segments to the metric
// of the combined path segment
var combinators = map[Quality]func(float64, float64) float64{
	Latency: func(a, b float64) float64 {
		return a + b
	},
	Throughput: math.Min,
}

// Combines metrics of two path segment to the metric of the segments combined
func (q Quality) Combine(l, r float64) float64 {
	return combinators[q](l, r)
}

type Extension struct {
	Uniquifier uint32
	Direction  Direction
	Quality    Quality
}

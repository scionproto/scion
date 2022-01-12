package pqa_extension

import (
	"math"

	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

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

var dir2pb = map[Direction]cppb.OptimizationDirection{
	Forward:   cppb.OptimizationDirection_FORWARD,
	Backward:  cppb.OptimizationDirection_BACKWARD,
	Symmetric: cppb.OptimizationDirection_SYMMETRIC,
}

func (d Direction) ToPB() cppb.OptimizationDirection {
	return dir2pb[d]
}

func DirectionFromPB(pbDirection cppb.OptimizationDirection) Direction {
	for q, pbqc := range dir2pb {
		if pbqc == pbDirection {
			return q
		}
	}
	panic("unknown path quality")
}

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

// Tolerance for metrics of a path to be considered "symmetric"
// A path with forward metric fwd and backward metric bwd is considered
// symmetric if abs(fwd - bwd) <= symTol * max(abs(fwd), abs(bwd))
var symTols = map[Quality]float64{
	Latency:    0.1,
	Throughput: 0.1,
}

// Commutative. Returns true if a path with forward metric a
// and backward metric b should be considered symmetric in that metric.
func (q Quality) AreSymmetric(a float64, b float64) bool {
	return math.Abs(a-b) <= symTols[q]*math.Max(math.Abs(a), math.Abs(b))
}

var combinators = map[Quality]func(float64, float64) float64{
	Latency: func(a, b float64) float64 {
		return a + b
	},
	Throughput: math.Max,
}

func (q Quality) Combine(l, r float64) float64 {
	return combinators[q](l, r)
}

// Maps quality type here to quality type in protobuf
var quality2pb = map[Quality]cppb.OptimizationQuality{
	Latency:    cppb.OptimizationQuality_LATENCY,
	Throughput: cppb.OptimizationQuality_BANDWITH,
}

func (q Quality) ToPB() cppb.OptimizationQuality {
	return quality2pb[q]
}

func QualityFromPB(pbQuality cppb.OptimizationQuality) Quality {
	for q, pbqc := range quality2pb {
		if pbqc == pbQuality {
			return q
		}
	}
	panic("unknown path quality")
}

type Extension struct {
	Uniquifier uint32
	Direction  Direction
	Quality    Quality
}

func (e *Extension) ToPB() *cppb.PathQualityAwareExtension {
	if e == nil {
		return nil
	}
	return &cppb.PathQualityAwareExtension{
		Quality:    e.Quality.ToPB(),
		Uniquifier: uint32(e.Uniquifier),
		Direction:  e.Direction.ToPB(),
	}
}

func ExtensionFromPB(e *cppb.PathQualityAwareExtension) *Extension {
	if e == nil {
		panic("Missing extension.")
	}

	return &Extension{
		Quality:    QualityFromPB(e.Quality),
		Direction:  DirectionFromPB(e.Direction),
		Uniquifier: e.Uniquifier,
	}
}

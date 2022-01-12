package pqa_extension

import (
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

type Direction uint8

const (
	Forward = iota
	Backward
	Symmetric
)

// Maps Direction type here to Direction type in protobuf
var Direction2PB = map[Direction]cppb.OptimizationDirection{
	Forward:   cppb.OptimizationDirection_FORWARD,
	Backward:  cppb.OptimizationDirection_BACKWARD,
	Symmetric: cppb.OptimizationDirection_SYMMETRIC,
}

// Reverses the Quality2PB map
func PB2Direction(pbq cppb.OptimizationDirection) Direction {
	for q, pbqc := range Direction2PB {
		if pbqc == pbq {
			return q
		}
	}
	// TODO Backwards compatibility
	panic("unknown path quality")
}

type Quality uint8

const (
	NoQuality = 0
	Latency   = iota + 1
	Throughput
)

func (q Quality) IsZero() bool {
	return q == NoQuality
}

// Maps quality type here to quality type in protobuf
var Quality2PB = map[Quality]cppb.OptimizationQuality{
	Latency:    cppb.OptimizationQuality_LATENCY,
	Throughput: cppb.OptimizationQuality_BANDWITH,
}

// Reverses the Quality2PB map
func PB2Quality(pbq cppb.OptimizationQuality) Quality {
	for q, pbqc := range Quality2PB {
		if pbqc == pbq {
			return q
		}
	}
	// TODO Backwards compatibility
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
		Quality:    Quality2PB[e.Quality],
		Uniquifier: uint32(e.Uniquifier),
		Direction:  Direction2PB[e.Direction],
	}
}

func FromPB(e *cppb.PathQualityAwareExtension) *Extension {
	if e == nil {
		panic("Missing extension.")
	}

	return &Extension{
		Quality:    PB2Quality(e.Quality),
		Direction:  PB2Direction(e.Direction),
		Uniquifier: e.Uniquifier,
	}
}

func (e *Extension) IsZero() bool {
	return e.Quality.IsZero()
}

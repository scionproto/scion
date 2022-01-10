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

type Quality uint8

const (
	Latency = iota
	Throughput
)

// Maps quality type here to quality type in protobuf
var Quality2PB = map[Quality]cppb.OptimizationQuality{
	Latency:    cppb.OptimizationQuality_LATENCY,
	Throughput: cppb.OptimizationQuality_BANDWITH,
}

type Extension struct {
	Uniquifier uint16
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

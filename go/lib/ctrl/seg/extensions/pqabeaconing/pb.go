package pqa_extension

import (
	cppb "github.com/scionproto/scion/go/pkg/proto/control_plane"
)

// Maps direction to its protobuf representation
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
		return nil
	}

	return &Extension{
		Quality:    QualityFromPB(e.Quality),
		Direction:  DirectionFromPB(e.Direction),
		Uniquifier: e.Uniquifier,
	}
}

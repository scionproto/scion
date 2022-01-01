package pqa

import (
	"errors"
	"math"
)

type Ifid string

type StaticSettings struct {
	NoPathsPerOptimizationTarget uint16
	PathQualities                map[PathQualityIdentifier]PathQuality
	PathQualityByName            map[string]PathQualityIdentifier
}

type OriginationSettings struct {
	OptimizationTargets map[OptimizationTargetIdentifier]OptimizationTarget
	OriginationOrder    map[Ifid][][]OptimizationTargetIdentifier
}

type PropagationSettings struct {
	IdentifierToInterfaceGroup          map[InterfaceGroupIdentifier]InterfaceGroup
	QualityToDirectionToInterfaceGroups map[PathQualityIdentifier]map[OptimizationDirection][]InterfaceGroupIdentifier
}

type Extension struct {
	StaticSettings
	OriginationSettings
	PropagationSettings
}

type InterfaceGroupIdentifier string
type InterfaceGroup []Ifid

type OptimizationTargetIdentifier string

const (
	OptimizationTargetNO_TARGET OptimizationTargetIdentifier = "NO_TARGET"
)

type PathQuality struct {
	CombinationType   CombinationType
	OptimalityType    OptimalityType
	SymmetryTolerance float64
}

type PathQualityMetricValue struct {
	Value   float64
	Quality PathQualityIdentifier
}

type PathQualityIdentifier string

type CombinationType string

const (
	CombinationTypeAdditive       CombinationType = "additive"
	CombinationTypeMultiplicative CombinationType = "multiplicative"
	CombinationTypeMax            CombinationType = "max"
	CombinationTypeMin            CombinationType = "min"
)

type OptimalityType string

const (
	OptimalityTypeMax OptimalityType = "max"
	OptimalityTypeMin OptimalityType = "min"
)

type OptimizationDirection string

const (
	OptimizationDirectionForward   OptimizationDirection = "forward"
	OptimizationDirectionBackward  OptimizationDirection = "backward"
	OptimizationDirectionSymmetric OptimizationDirection = "symmetric"
)

type OptimizationTarget struct {
	Uniquifier uint8
	Quality    PathQualityIdentifier
	Direction  OptimizationDirection
}

func (optt *Extension) GetOptimizationTargetsForInterface(ifid Ifid, interval uint) []OptimizationTarget {
	if len(optt.OriginationOrder[ifid]) == 0 {
		return nil
	}

	interval = interval % uint(len(optt.OriginationOrder[ifid]))
	var targets []OptimizationTarget
	for _, idx := range optt.OriginationOrder[ifid][interval] {
		targets = append(targets, optt.OptimizationTargets[OptimizationTargetIdentifier(idx)])
	}

	return targets
}

func (quality *PathQuality) Combine(q1 float64, q2 float64) (float64, error) {
	switch quality.CombinationType {
	case CombinationTypeAdditive:
		return q1 + q2, nil
	case CombinationTypeMultiplicative:
		return q1 * q2, nil
	case CombinationTypeMax:
		return math.Max(q1, q2), nil
	case CombinationTypeMin:
		return math.Min(q1, q2), nil
	default:
		return 0., errors.New("unknown Path Quality Combination Type")
	}
}

func (quality *PathQuality) IsWithinSymmetryTolerance(q1 float64, q2 float64) bool {
	minV := math.Abs(q2) * (1 - quality.SymmetryTolerance)
	maxV := math.Abs(q2) * (1 + quality.SymmetryTolerance)
	q1AbsV := math.Abs(q1)
	return minV <= q1AbsV && q1AbsV <= maxV
}

// Returns true iff q1 is better than q2
func (quality *PathQuality) Compare(q1 float64, q2 float64) bool {
	switch quality.OptimalityType {
	case OptimalityTypeMax:
		return q1 > q2
	case OptimalityTypeMin:
		return q1 < q2
	default:
		return false
	}
}

func (propSettings *PropagationSettings) GetInterfaceGroupsForDirectionAndQuality(
	quality PathQualityIdentifier, direction OptimizationDirection) []*InterfaceGroup {
	ifaceGroup := propSettings.QualityToDirectionToInterfaceGroups[quality][direction]
	var groups []*InterfaceGroup
	for _, id := range ifaceGroup {
		ident := propSettings.IdentifierToInterfaceGroup[InterfaceGroupIdentifier(id)]
		groups = append(groups, &ident)
	}
	return groups
}

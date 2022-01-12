package pqa

import (
	"context"
	"math"

	pqacfg "github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa/config"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	pqa_extension "github.com/scionproto/scion/go/lib/ctrl/seg/extensions/pqabeaconing"
	"github.com/scionproto/scion/go/lib/serrors"
)

// TODO: Take types from extension, don't redefine them here

type Ifid string

type GlobalParamsSingleton struct {
	NoPathsPerOptimizationTarget uint16
	PathQualities                map[PathQualityIdentifier]PathQuality
}

type OriginationSettings struct {
	OptimizationTargets map[OptimizationTargetIdentifier]OptimizationTarget
	Orders              map[uint16][][]OptimizationTarget
	Intervals           map[uint16]uint
}

type PropagationSettings struct {
	IdentifierToInterfaceGroup          map[InterfaceGroupIdentifier]InterfaceGroup
	QualityToDirectionToInterfaceGroups map[PathQualityIdentifier]map[OptimizationDirection][]InterfaceGroupIdentifier
}

type Settings struct {
	Global      GlobalParamsSingleton
	Origination OriginationSettings
	Propagation PropagationSettings
}

func NewSettings(cfgYamlPath string) (Settings, error) {
	gset := GlobalParams

	// Load config file
	pqaCfg, err := pqacfg.LoadPqaCfgFromYAML(cfgYamlPath)
	if err != nil {
		return Settings{}, err
	}

	// Parse originator config struct
	orig, err := NewOriginationSettings(pqaCfg.Origination, gset)
	if err != nil {
		return Settings{}, err
	}

	// Parse propagator config struct
	prop, err := NewPropagationSettings(&pqaCfg.Propagation)
	if err != nil {
		return Settings{}, err
	}

	return Settings{
		Origination: *orig,
		Propagation: *prop,
		Global:      gset,
	}, nil
}

type InterfaceGroupIdentifier string
type InterfaceGroup []uint16

type OptimizationTargetIdentifier string

const (
	OptimizationTargetNO_TARGET OptimizationTargetIdentifier = "NO_TARGET"
)

type PathQualityMetricValue struct {
	Value   float64
	Quality PathQualityIdentifier
}

/* ------------------------------------ */
// Global Algorithm Parameters

// Types of combining metrics of subpaths to get a metric of the whole path
type CombinationType string

const (
	Additive       CombinationType = "additive"
	Multiplicative CombinationType = "multiplicative"
	CMax           CombinationType = "max"
	CMin           CombinationType = "min"
)

// Types of optimization (min or max)
type OptimalityType string

const (
	Max OptimalityType = "max"
	Min OptimalityType = "min"
)

// Possible directions of optimization (forwad, backwad or symmetric)
type OptimizationDirection string

const (
	Forward   OptimizationDirection = "forward"
	Backward  OptimizationDirection = "backward"
	Symmetric OptimizationDirection = "symmetric"
)

func (d *OptimizationDirection) ExtensionDirection() (pqa_extension.Direction, error) {
	switch *d {
	case Forward:
		return pqa_extension.Forward, nil
	case Backward:
		return pqa_extension.Backward, nil
	case Symmetric:
		return pqa_extension.Symmetric, nil
	default:
		return 0, serrors.New("unknown optimazation direction")
	}
}

// Identifies a path quality, e.g. "latency"
type PathQualityIdentifier string

const (
	QualityThroughput = "throughput"
	QualityLatency    = "latency"
)

type PathQuality struct {
	combinationType   CombinationType
	optimalityType    OptimalityType
	symmetryTolerance float64

	identifier PathQualityIdentifier
}

func (q PathQuality) String() string {
	return string(q.identifier)
}

func (q PathQuality) ExtensionQuality() (pqa_extension.Quality, error) {
	switch q.identifier {
	case QualityLatency:
		return pqa_extension.Latency, nil
	case QualityThroughput:
		return pqa_extension.Throughput, nil
	default:
		return 0, serrors.New("Unknown quality identifier", "identifier", q.identifier)
	}
}

func (q PathQuality) IsNil() bool {
	return q.identifier == ""
}

var GlobalParams = GlobalParamsSingleton{
	NoPathsPerOptimizationTarget: 5,
	PathQualities: map[PathQualityIdentifier]PathQuality{
		QualityThroughput: {
			combinationType:   CMin,
			optimalityType:    Max,
			symmetryTolerance: 0.1,
			identifier:        QualityThroughput,
		},
		QualityLatency: {
			combinationType:   Additive,
			optimalityType:    Min,
			symmetryTolerance: 0.1,
			identifier:        QualityLatency,
		},
	},
}

func GetPathQuality(ident PathQualityIdentifier) (*PathQuality, error) {
	return GlobalParams.PathQuality(ident)
}

func (s *GlobalParamsSingleton) PathQuality(ident PathQualityIdentifier) (*PathQuality, error) {
	if q, ok := s.PathQualities[ident]; ok {
		return &q, nil
	} else {
		return nil, serrors.New("Unknown path quality identifier", "identifier", ident)
	}
}

// Given metrics for path a -> b and b -> c,
// Calculate the metric for path a -> b -> c
func (quality PathQuality) Combine(q1 float64, q2 float64) float64 {
	switch quality.combinationType {
	case Additive:
		return q1 + q2
	case Multiplicative:
		return q1 * q2
	case CMax:
		return math.Max(q1, q2)
	case CMin:
		return math.Min(q1, q2)
	default:
		panic("Unknown combination type") // This should never happen
	}
}

// Returns true if two metric values a, b are close enough to be considered "identical"
func (quality PathQuality) IsWithinSymmetryTolerance(q1 float64, q2 float64) bool {
	minV := math.Abs(q2) * (1 - quality.symmetryTolerance)
	maxV := math.Abs(q2) * (1 + quality.symmetryTolerance)
	q1AbsV := math.Abs(q1)
	return minV <= q1AbsV && q1AbsV <= maxV
}

// True iff q1 is worse than q2 i.t.o. quality
func (quality PathQuality) Less(q1 float64, q2 float64) bool {
	switch quality.optimalityType {
	case Max:
		return q1 < q2
	case Min:
		return q1 > q2
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

type OptimizationTarget struct {
	Quality    PathQuality
	Uniquifier uint32
	Direction  OptimizationDirection
}

func qualityFromExtension(ext pqa_extension.Quality) (PathQualityIdentifier, error) {
	switch ext {
	case pqa_extension.Latency:
		return QualityLatency, nil
	case pqa_extension.Throughput:
		return QualityThroughput, nil
	default:
		return "", serrors.New("Unknown quality identifier", "identifier", ext)
	}
}

func directionFromExtension(ext pqa_extension.Direction) (OptimizationDirection, error) {
	switch ext {
	case pqa_extension.Forward:
		return Forward, nil
	case pqa_extension.Backward:
		return Backward, nil
	case pqa_extension.Symmetric:
		return Symmetric, nil
	default:
		return "", serrors.New("Unknown direction identifier", "identifier", ext)
	}
}

func TargetFromExtension(ext pqa_extension.Extension) OptimizationTarget {
	qIdent, err := qualityFromExtension(ext.Quality)
	q, err := GlobalParams.PathQuality(qIdent)
	if err != nil {
		panic(err)
	}

	direction, err := directionFromExtension(ext.Direction)
	if err != nil {
		panic(err)
	}

	return OptimizationTarget{
		Quality:    *q,
		Uniquifier: ext.Uniquifier,
		Direction:  direction,
	}
}

// Make optimization target an Extension
func (t OptimizationTarget) Extend(ctx context.Context, ext *seg.Extensions, ingress, egress uint16, peers []uint16) error {
	// Return without adding the extension if no quality is specified
	if t.Quality.IsNil() {
		return nil
	}
	// Convert direction to respective extension type
	dir, err := t.Direction.ExtensionDirection()
	if err != nil {
		return err
	}

	// Convert quality to respective extension type
	qua, err := t.Quality.ExtensionQuality()
	if err != nil {
		return err
	}

	// Attach extension to ext field
	ext.PqaExtension = &pqa_extension.Extension{
		Uniquifier: t.Uniquifier,
		Direction:  dir,
		Quality:    qua,
	}
	return nil
}

func NewOriginationSettings(cfg pqacfg.OriginatorCfg, gset GlobalParamsSingleton) (*OriginationSettings, error) {
	oset := OriginationSettings{}

	oset.OptimizationTargets = make(map[OptimizationTargetIdentifier]OptimizationTarget)
	oset.Orders = make(map[uint16][][]OptimizationTarget, 0)

	for ident, otCfg := range cfg.OptimizationTargets {
		q, err := gset.PathQuality(PathQualityIdentifier(otCfg.Quality))
		if err != nil {
			return nil, err
		}
		oset.OptimizationTargets[OptimizationTargetIdentifier(ident)] = OptimizationTarget{
			Quality:    *q,
			Direction:  OptimizationDirection(otCfg.Direction),
			Uniquifier: otCfg.Uniquifier,
		}
	}

	for intfId, origCfg := range cfg.OriginationCfgs {
		intfOrigOrder := make([][]OptimizationTarget, 0)
		for _, origIntervalCfg := range origCfg {

			origInterval := make([]OptimizationTarget, 0)
			for _, optimTarget := range origIntervalCfg {
				origInterval = append(origInterval, oset.OptimizationTargets[OptimizationTargetIdentifier(optimTarget)])
			}
			intfOrigOrder = append(intfOrigOrder, (origInterval))
		}
		new_id, err := intfId.Uint16()
		if err != nil {
			return &oset, err
		}
		oset.Orders[new_id] = intfOrigOrder
	}

	return &oset, nil
}

func NewPropagationSettings(cfg *pqacfg.PropagatorCfg) (*PropagationSettings, error) {

	set := PropagationSettings{}
	for ifaceGroupName, ifaceGroupCfg := range *cfg {

		// Create map Interface group identifier -> list interfaces
		igrp := make(InterfaceGroup, 0)
		for _, ifaceIdentifier := range ifaceGroupCfg.Interfaces {
			igrp = append(igrp, ifaceIdentifier)
		}

		igrpIdent := InterfaceGroupIdentifier(ifaceGroupName)
		set.IdentifierToInterfaceGroup = make(map[InterfaceGroupIdentifier]InterfaceGroup)
		set.QualityToDirectionToInterfaceGroups = make(map[PathQualityIdentifier]map[OptimizationDirection][]InterfaceGroupIdentifier)

		set.IdentifierToInterfaceGroup[igrpIdent] = igrp

		// Create map quality -> direction -> interface group identifier
		for _, oFilter := range ifaceGroupCfg.OptimizationTargetFilters {
			quality := PathQualityIdentifier(oFilter.Quality)
			var directions []OptimizationDirection
			if oFilter.Direction != "" {
				directions = []OptimizationDirection{OptimizationDirection(oFilter.Direction)}
			} else {
				directions = []OptimizationDirection{Forward, Backward}
			}

			for _, direction := range directions {
				if _, ok := set.QualityToDirectionToInterfaceGroups[quality]; !ok {
					set.QualityToDirectionToInterfaceGroups[quality] = make(map[OptimizationDirection][]InterfaceGroupIdentifier)
				}
				if _, ok := set.QualityToDirectionToInterfaceGroups[quality][direction]; !ok {
					set.QualityToDirectionToInterfaceGroups[quality][direction] = make([]InterfaceGroupIdentifier, 0)
				}
				set.QualityToDirectionToInterfaceGroups[quality][direction] = append(set.QualityToDirectionToInterfaceGroups[quality][direction], igrpIdent)
			}
		}

	}

	return &set, nil
}

// Generates "sample" settings based on a file (see comments in file) for test infrastructure
func GenerateSettingsForInterfaces(intfs *ifstate.Interfaces) Settings {
	genSet, err := NewSettings("pqa-configs/genConfig.yml")
	if err != nil {
		panic(err)
	}
	set := Settings{
		Global: genSet.Global,
		Origination: OriginationSettings{
			OptimizationTargets: genSet.Origination.OptimizationTargets,
			Orders:              make(map[uint16][][]OptimizationTarget, 0),
			Intervals:           make(map[uint16]uint),
		},
	}

	// Extract list of all orders in genConfig
	orders := make([][][]OptimizationTarget, 0)
	for _, order := range genSet.Origination.Orders {
		orders = append(orders, order)
	}

	intf_c := 0
	// Apply orders from the gen set
	if len(genSet.Origination.Orders) > 0 {
		for ifid := range intfs.All() {
			// Get next order
			order := orders[uint16(intf_c%len(orders))]
			intf_c++
			// Set that order for current interface
			set.Origination.Orders[ifid] = order
			set.Origination.Intervals[ifid] = uint(0)
		}
	} else {
		panic("no orders")
	}

	set.Origination.Orders[20] = nil
	set.Origination.Orders[21] = make([][]OptimizationTarget, 0)
	return set
}

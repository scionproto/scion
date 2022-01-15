package pqa

import (
	"context"
	"fmt"

	pqacfg "github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa/config"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	extension "github.com/scionproto/scion/go/lib/ctrl/seg/extensions/pqabeaconing"
	"github.com/scionproto/scion/go/lib/serrors"
)

const N = 5

type Settings struct {
	Origination
	Propagation
}

type Origination struct {
	// Stores the order of origination for each interface
	Orders map[uint16][][]Target

	// Stores which interface has originated which interval last
	Intervals map[uint16]uint
}

// Keys into the map storing interface groups given quality & direction
type targetKey struct {
	quality   extension.Quality
	direction extension.Direction
}
type Propagation struct {
	// Maps quality -> direction -> interface group
	q2d2group map[targetKey][][]*ifstate.Interface
}

func (p *Propagation) GetInterfaceGroups(q extension.Quality, d extension.Direction) [][]*ifstate.Interface {
	return p.q2d2group[targetKey{q, d}]
}

func LoadSettings(cfgYamlPath string, ifaces *ifstate.Interfaces) (Settings, error) {
	// Load config file
	pqaCfg, err := pqacfg.LoadPqaCfgFromYAML(cfgYamlPath)
	if err != nil {
		return Settings{}, err
	}

	// Parse originator config struct
	orig, err := NewOriginationSettings(pqaCfg.Origination)
	if err != nil {
		return Settings{}, err
	}

	// Parse propagator config struct
	prop, err := NewPropagationSettings(&pqaCfg.Propagation, ifaces)
	if err != nil {
		return Settings{}, err
	}

	return Settings{
		Origination: *orig,
		Propagation: *prop,
	}, nil
}

type InterfaceGroupIdentifier string
type InterfaceGroup []*ifstate.Interface

func (t Target) Extend(ctx context.Context, ext *seg.Extensions, ingress, egress uint16, peers []uint16) error {

	ext.PqaExtension = &extension.Extension{
		Uniquifier: t.Uniquifier,
		Direction:  t.Direction,
		Quality:    t.Quality,
	}
	return nil
}

func NewOriginationSettings(cfg pqacfg.OriginatorCfg) (*Origination, error) {
	oset := Origination{}

	// Process targets
	targets := make(map[pqacfg.TargetIdentifier]Target)
	for targetId, targetCfg := range cfg.Targets {
		target := Target{
			Quality:    targetCfg.Quality.Quality(),
			Direction:  targetCfg.Direction.Direction(),
			Uniquifier: targetCfg.Uniquifier,
		}

		targets[targetId] = target
	}

	// Read in origination orders
	orders := make(map[uint16][][]Target)
	for intfId, intfCfg := range cfg.OriginationCfgs {
		intfSettings := make([][]Target, 0)
		for _, intervalCfg := range intfCfg {
			interval := make([]Target, 0)
			for _, targetId := range intervalCfg {
				interval = append(interval, targets[targetId])
			}
			intfSettings = append(intfSettings, interval)
		}
		orders[intfId] = intfSettings
	}
	oset.Orders = orders
	return &oset, nil
}

func NewPropagationSettings(cfg *pqacfg.PropagatorCfg, ifaces *ifstate.Interfaces) (*Propagation, error) {
	q2d2group := make(map[targetKey][][]*ifstate.Interface)
	for _, ifaceGroupCfg := range *cfg {
		ifGroup := make(InterfaceGroup, 0)
		for _, ifaceIdentifier := range ifaceGroupCfg.Interfaces {
			if intf := ifaces.Get(ifaceIdentifier); intf != nil {
				ifGroup = append(ifGroup, intf)
			} else {
				return nil, serrors.New("interface not found", "iface", ifaceIdentifier, "have", ifaces.All())
			}
		}
		for i, filter := range ifaceGroupCfg.OptimizationTargetFilters {
			if filter.Quality == "" {
				return nil, serrors.New(fmt.Sprintf("optimization target filter %d: Must specify quality", i))
			}

			q := filter.Quality.Quality()
			if filter.Direction == "" {
				// if direction is unspecified, add filters in both directions
				k1, k2 := targetKey{q, extension.Forward}, targetKey{q, extension.Backward}
				q2d2group[k1] = append(q2d2group[k1], ifGroup)
				q2d2group[k2] = append(q2d2group[k2], ifGroup)
			} else {
				// else add in the direction specified
				k := targetKey{q, filter.Direction.Direction()}
				q2d2group[k] = append(q2d2group[k], ifGroup)
			}
		}
	}
	return &Propagation{
		q2d2group: q2d2group,
	}, nil
}

var targets = map[pqacfg.TargetIdentifier]pqacfg.TargetCfg{
	"latency_1": {
		Quality:    "latency",
		Direction:  "forward",
		Uniquifier: 1,
	},
	"throughput_1": {
		Quality:    "throughput",
		Direction:  "forward",
		Uniquifier: 1,
	},
}

// var originationOrders = [][][]pqacfg.TargetIdentifier{
// 	{
// 		{
// 			"latency_1",
// 			"NO_TARGET",
// 		},
// 		{
// 			"throughput_1",
// 		},
// 	},
// 	{
// 		{
// 			"NO_TARGET",
// 		},
// 	},
//}

// for now, originate beacons for all targets on all interfaces
var originationOrders = [][][]pqacfg.TargetIdentifier{
	{
		{
			"latency_1",
			"throughput_1",
		},
	},
}

var targetFilters = []pqacfg.OptimizationTargetFilter{
	{
		Quality: "latency",
	}, {
		Quality: "throughput",
	},
}

// Generate sample settings
func GenerateSettingsForInterfaces(intfs *ifstate.Interfaces) (*Settings, error) {

	// Assign origination orders to interfacews - cycle through orders defined in originationOrders
	origOrders := make(map[uint16][][]pqacfg.TargetIdentifier)
	c := 0
	for intfId := range intfs.All() {
		origOrders[intfId] = originationOrders[c%len(originationOrders)]
		c++
	}

	// Create originator config
	origCfg := pqacfg.OriginatorCfg{
		Targets:         targets,
		OriginationCfgs: origOrders,
	}

	// Extract interfaces to list
	intfList := make([]uint16, 0)
	for ifid := range intfs.All() {
		intfList = append(intfList, ifid)
	}

	// Create propagation config
	propaCfg := make(pqacfg.PropagatorCfg)

	// Assign interfaces into groups of k...
	// const k = 2
	// maxIntefaceIdx := len(intfList) - (len(intfList) % k) // ...ignoring intfs that can't be put into groups of k
	// f := 0
	// for i := 0; i < maxIntefaceIdx; i += k {
	// 	ifaceGroup := pqacfg.InterfaceGroupCfg{
	// 		Interfaces:                intfList[i : i+k],
	// 		OptimizationTargetFilters: targetFilters,
	// 	}
	// 	// generate identifier
	// 	ifacegroupIdentifier := pqacfg.InterfaceGroupIdentifier(fmt.Sprintf("group_%d", f))
	// 	// create grouphope
	// 	propaCfg[ifacegroupIdentifier] = ifaceGroup
	// 	f++
	// }

	// create a single interface gorup targeting all targets and interfaces
	propaCfg["papa_group"] = pqacfg.InterfaceGroupCfg{
		Interfaces:                intfList,
		OptimizationTargetFilters: targetFilters,
	}

	orig, err := NewOriginationSettings(origCfg)
	if err != nil {
		return nil, err
	}

	prop, err := NewPropagationSettings(&propaCfg, intfs)
	if err != nil {
		return nil, err
	}

	return &Settings{
		Origination: *orig,
		Propagation: *prop,
	}, nil

}

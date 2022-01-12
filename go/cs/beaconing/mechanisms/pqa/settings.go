package pqa

import (
	"context"
	"fmt"

	pqacfg "github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa/config"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	extension "github.com/scionproto/scion/go/lib/ctrl/seg/extensions/pqabeaconing"
	"github.com/scionproto/scion/go/lib/serrors"
)

type Target struct {
	Quality    extension.Quality
	Direction  extension.Direction
	Uniquifier uint32
	ISD        addr.ISD
	AS         addr.AS
}

type OriginationSettings struct {
	Orders map[uint16][][]Target

	// Stores which interface has originated which interval last
	Intervals map[uint16]uint
}

type PropagationSettings struct {
	// Maps quality -> direction -> interface group
	q2d2group map[extension.Quality]map[extension.Direction][]*ifstate.Interface
}

func (p *PropagationSettings) GetInterfaceGroups(q extension.Quality, d extension.Direction) []*ifstate.Interface {
	return p.q2d2group[q][d]
}

const N = 5

type Settings struct {
	Origination OriginationSettings
	Propagation PropagationSettings
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

type OptimizationTargetIdentifier string

const (
	OptimizationTargetNO_TARGET OptimizationTargetIdentifier = "NO_TARGET"
)

func (t Target) Extend(ctx context.Context, ext *seg.Extensions, ingress, egress uint16, peers []uint16) error {

	ext.PqaExtension = &extension.Extension{
		Uniquifier: t.Uniquifier,
		Direction:  t.Direction,
		Quality:    t.Quality,
	}
	return nil
}

func NewOriginationSettings(cfg pqacfg.OriginatorCfg) (*OriginationSettings, error) {
	oset := OriginationSettings{}

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

func NewPropagationSettings(cfg *pqacfg.PropagatorCfg, ifaces *ifstate.Interfaces) (*PropagationSettings, error) {
	// Create map quality -> direction -> list interface groups
	q2d2group := make(map[extension.Quality]map[extension.Direction][]*ifstate.Interface)
	for _, ifaceGroupCfg := range *cfg {
		ifGroup := make(InterfaceGroup, 0)
		for _, ifaceIdentifier := range ifaceGroupCfg.Interfaces {
			ifGroup = append(ifGroup, ifaces.Get(ifaceIdentifier))
		}
		for i, filter := range ifaceGroupCfg.OptimizationTargetFilters {
			if filter.Quality == "" {
				return nil, serrors.New(fmt.Sprintf("optimization target filter %d: Must specify quality", i))
			}
			q := filter.Quality.Quality()

			// Create new direction -> iface group map if it doesn't exist
			if _, ok := q2d2group[q]; !ok {
				q2d2group[q] = make(map[extension.Direction][]*ifstate.Interface)
			}
			// Grab it
			d2group := q2d2group[q]

			if filter.Direction == "" {
				// Append ifstate group to both directions if no direction is specified
				d2group[extension.Forward] = append(d2group[extension.Forward], ifGroup...)
				d2group[extension.Backward] = append(d2group[extension.Backward], ifGroup...)
			} else {
				// Else append to specified direction
				d := filter.Direction.Direction()
				d2group[d] = append(d2group[d], ifGroup...)
			}
		}
	}

	return &PropagationSettings{
		q2d2group: q2d2group,
	}, nil
}

// Generates "sample" settings based on a file (see comments in file) for test infrastructure
func GenerateSettingsForInterfaces(intfs *ifstate.Interfaces) Settings {
	genSet, err := LoadSettings("pqa-configs/genConfig.yml", intfs)
	if err != nil {
		panic(err)
	}
	set := Settings{
		Origination: OriginationSettings{
			Orders:    make(map[uint16][][]Target, 0),
			Intervals: make(map[uint16]uint),
		},
	}

	// Extract list of all orders in genConfig
	orders := make([][][]Target, 0)
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

	// TODO: Remove
	set.Origination.Orders[20] = nil
	set.Origination.Orders[21] = make([][]Target, 0)
	return set
}

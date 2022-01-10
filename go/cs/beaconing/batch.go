package beaconing

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/log"
)

// A batch of beacons ready to be sent, intf -> bcn means bcn should be sent on intf
type SendableBeaconsBatch map[*ifstate.Interface][]beacon.Beacon

// Turns the map into a map[uint16][]
func (b SendableBeaconsBatch) String() string {
	newMap := make(map[uint16][]beacon.Beacon)
	for intf, bcns := range b {
		newMap[intf.TopoInfo().ID] = bcns
	}
	if res, err := json.Marshal(newMap); err == nil {
		return string(res[:])
	} else {
		return fmt.Sprintf("error serializing to json: %v", err)
	}
}

// Removes beacons from intf2bcns that are looping back to the same AS.
func (batch SendableBeaconsBatch) FilterLooping(allowIsdLoop bool) {
	for intf := range batch {
		filtered := batch[intf][:0] // Use slice aliased to original list to avoid copying
		for _, bcn := range batch[intf] {
			if err := beacon.FilterLoop(bcn, intf.TopoInfo().IA, allowIsdLoop); err == nil {
				filtered = append(filtered, bcn)
			}
		}
		batch[intf] = filtered
	}
}

// Extends beacons with the interfaces they should be sent on
func (batch SendableBeaconsBatch) ExtendBeacons(ctx context.Context, extender Extender, peers []uint16) error {
	for egIntf, bcns := range batch {
		egIntfId := egIntf.TopoInfo().ID
		for _, bcn := range bcns {
			if err2 := extender.Extend(ctx, bcn.Segment, bcn.InIfId, egIntfId, peers, nil); err2 != nil {
				return err2
			}
		}
	}
	return nil
}

// Deepcopies all beacons to avoid race conditions; skips beacons where deepcopy fails
func (batch SendableBeaconsBatch) DeepCopyBeacons(ctx context.Context) {
	logger := log.FromCtx(ctx)
	for intf, bcns := range batch {
		bcns_copied := bcns[:0]
		for _, bcn := range bcns {
			if copy, err := bcn.DeepCopy(); err != nil {
				logger.Debug("Unable to unpack beacon", "err", err)
				continue
			} else {
				bcns_copied = append(bcns_copied, copy)
			}
		}
		batch[intf] = bcns_copied
	}
}

package pqa

import (
	"context"
	"testing"
	"time"

	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/stretchr/testify/assert"
)

const (
	topo = "testdata/topo.json"
)

const (
	ifid1 = 1417
	ifid2 = 2712
)

func TestUpdateOriginationIntervals(t *testing.T) {
	scen := NewScenario(t, topo)

	tick := beaconing.NewTick(time.Hour)
	tick.SetNow(time.Now())
	// Mechanism with 2 interface configurations
	mech := Mechanism{
		AllInterfaces: scen.Interfaces,
		Settings: Settings{
			Origination: OriginationSettings{
				Intervals: map[uint16]uint{
					ifid1: 0,
					ifid2: 0,
				},
			},
		},
		Tick: tick,
	}

	// Set one to have originated recently
	if1 := scen.Interfaces.Get(ifid1)
	if1.Originate(tick.Now())
	// Forward tick by 1 second
	tick.SetNow(tick.Now().Add(time.Second))

	mech.updateOriginationIntervals(context.Background())

	// Now one should have increased, but not the other
	assert.Equal(t, mech.Settings.Origination.Intervals[ifid1], uint(0))
	assert.Equal(t, mech.Settings.Origination.Intervals[ifid2], uint(1))
}

func TestCreateOriginBeaconForTarget(t *testing.T) {
	scen := NewScenario(t, topo)

	sett := NewGlobalParams()

	target := OptimizationTarget{
		Quality:   sett.PathQualities[QualityLatency],
		Direction: Forward,
	}

	mech := Mechanism{
		Extender: scen.Extender(t),
	}

	exampleIfid := 1417

	bcn, err := mech.createOriginBeaconForTarget(context.Background(), uint16(exampleIfid), target)
	assert.NoError(t, err)
	assert.NoError(t, bcn.Segment.Validate(seg.ValidateBeacon))
}

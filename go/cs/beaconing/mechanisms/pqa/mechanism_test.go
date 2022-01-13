package pqa_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa"
	"github.com/scionproto/scion/go/cs/beaconing/mechanisms/pqa/mock_pqa"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	pqa_extension "github.com/scionproto/scion/go/lib/ctrl/seg/extensions/pqabeaconing"
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
	scen := pqa.NewScenario(t, topo)

	tick := beaconing.NewTick(time.Hour)
	tick.SetNow(time.Now())
	// Mechanism with 2 interface configurations
	mech := pqa.Mechanism{
		AllInterfaces: scen.Interfaces,
		Settings: pqa.Settings{
			Origination: pqa.Origination{
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

	mech.UpdateOriginationIntervals(context.Background())

	// Now one should have increased, but not the other
	assert.Equal(t, mech.Settings.Origination.Intervals[ifid1], uint(0))
	assert.Equal(t, mech.Settings.Origination.Intervals[ifid2], uint(1))
}

func TestCreateOriginBeaconForTarget(t *testing.T) {
	scen := pqa.NewScenario(t, topo)

	target := pqa.Target{
		Quality:   pqa_extension.Latency,
		Direction: pqa_extension.Forward,
	}

	mech := pqa.Mechanism{
		Extender: scen.Extender(t),
	}

	exampleIfid := 1417

	bcn, err := mech.CreateOriginBeaconForTarget(context.Background(), uint16(exampleIfid), target)
	assert.NoError(t, err)
	assert.NoError(t, bcn.Segment.Validate(seg.ValidateBeacon))
}

func TestCreatePropagationBatch(t *testing.T) {
	scen := pqa.NewScenario(t, topo)
	mctrl := gomock.NewController(t)

	db := mock_pqa.NewMockDB(mctrl)
	mech := pqa.Mechanism{
		AllInterfaces: scen.Interfaces,
		Settings:      scen.Settings,
		Tick:          scen.Tick,
		Extender:      scen.Extender(t),
		DB:            db,
	}

	ia1 := scen.Interfaces.Get(ifid1).TopoInfo().IA
	ia2 := scen.Interfaces.Get(ifid2).TopoInfo().IA

	db.EXPECT().BeaconSources(gomock.Any()).Return([]addr.IA{ia1, ia2}, nil)
	db.EXPECT().GetActiveTargets(gomock.Any(), gomock.Any()).Return([]pqa.Target{{
		Quality:    pqa_extension.Latency,
		Direction:  pqa_extension.Forward,
		Uniquifier: 0,
		ISD:        ia1.I,
		AS:         ia1.A,
	}}, nil)

	res, err := mech.ProvidePropagationBatch(context.Background(), mech.Tick)
	assert.NoError(t, err)
	assert.NotNil(t, res)
}

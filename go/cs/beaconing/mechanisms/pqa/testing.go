package pqa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"hash"
	"testing"
	"time"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/cs/beaconing"
	"github.com/scionproto/scion/go/cs/ifstate"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/seg"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/scrypto/signed"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/pkg/trust"
	"github.com/stretchr/testify/require"
	"inet.af/netaddr"
)

type Scenario struct {
	topology.Topology
	PrivKey *ecdsa.PrivateKey
	*ifstate.Interfaces
	beaconing.Tick
	Settings Settings
}

func NewScenario(t *testing.T, topoFile string) Scenario {
	topo, err := topology.FromJSONFile(topoFile)
	require.NoError(t, err)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	intfs := ifstate.NewInterfaces(interfaceInfos(topo), ifstate.Config{})

	tick := beaconing.NewTick(time.Hour)

	set, err := GenerateSettingsForInterfaces(intfs)
	require.NoError(t, err)
	return Scenario{
		Topology:   topo,
		PrivKey:    priv,
		Interfaces: intfs,
		Tick:       tick,
		Settings:   *set,
	}
}

func (s Scenario) Extender(t *testing.T) *beaconing.DefaultExtender {
	return &beaconing.DefaultExtender{
		IA:         s.IA(),
		MTU:        s.MTU(),
		Signer:     s.Signer(t),
		Intfs:      s.Interfaces,
		MAC:        macFactory,
		MaxExpTime: func() uint8 { return beacon.DefaultMaxExpTime },
		StaticInfo: func() *beaconing.StaticInfoCfg { return nil },
	}
}

func (s Scenario) Signer(t *testing.T) seg.Signer {
	return testSigner(t, s.PrivKey, s.IA())
}

func testSigner(t *testing.T, priv crypto.Signer, ia addr.IA) seg.Signer {
	return trust.Signer{
		PrivateKey: priv,
		Algorithm:  signed.ECDSAWithSHA256,
		IA:         ia,
		TRCID: cppki.TRCID{
			ISD:    ia.I,
			Base:   1,
			Serial: 21,
		},
		SubjectKeyID: []byte("skid"),
		Expiration:   time.Now().Add(time.Hour),
	}
}

func interfaceInfos(topo topology.Topology) map[uint16]ifstate.InterfaceInfo {
	in := topo.IFInfoMap()
	result := make(map[uint16]ifstate.InterfaceInfo, len(in))
	for id, info := range in {
		result[uint16(id)] = ifstate.InterfaceInfo{
			ID:           uint16(info.ID),
			IA:           info.IA,
			LinkType:     info.LinkType,
			InternalAddr: netaddr.MustParseIPPort(info.InternalAddr.String()),
			RemoteID:     uint16(info.RemoteIFID),
			MTU:          uint16(info.MTU),
		}
	}
	return result
}

var macFactory = func() hash.Hash {
	mac, err := scrypto.InitMac(make([]byte, 16))
	// This can only happen if the library is messed up badly.
	if err != nil {
		panic(err)
	}
	return mac
}

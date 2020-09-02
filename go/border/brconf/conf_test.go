// Copyright 2019 Anapaya Systems

package brconf_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/border/brconf"
	"github.com/scionproto/scion/go/lib/topology"
)

func TestLoad(t *testing.T) {
	tests := map[string]struct {
		ExpectedTopo func(t *testing.T) topology.Topology
	}{
		"base": {
			ExpectedTopo: func(t *testing.T) topology.Topology {
				expectedTopo, err := topology.FromJSONFile("testdata/topology.json")
				require.NoError(t, err)
				return expectedTopo
			},
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c, err := brconf.Load("br1-ff00_0_110-2", "testdata")
			assert.NoError(t, err)
			assert.NotNil(t, c)
			expectedTopo := test.ExpectedTopo(t)
			assert.Equal(t, expectedTopo, c.Topo)
		})
	}
}

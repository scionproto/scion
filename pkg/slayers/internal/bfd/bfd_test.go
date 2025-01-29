// Copyright 2021 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// package bfd_test contains tests for parsing SCION/BFD packets with the slayer package.
// This is in a separate package because slayers / slayers_test does not import
// gopacket/layers but we also want to check the behaviour for when we do import
// this gopacket/layers.
package bfd_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/slayers"
)

var testdataDir = "../../testdata/"

func TestBFDLayerTypeDefinition(t *testing.T) {
	// We want to check that the constant ID used in slayers.layerTypeBFD matches
	// the actual ID of gopacket/layers.LayerTypeBFD. As slayers.layerTypeBFD is
	// not exported, we check this via SCION.NextLayerType instead.
	// If this does not match then either there is a bug in the NextLayerType
	// logic or the constant used to define the slayers.layerTypeBFD does not
	// match gopacket/layers.LayerTypeBFD.
	scn := &slayers.SCION{}
	scn.NextHdr = slayers.L4BFD
	assert.Equal(t, scn.NextLayerType(), layers.LayerTypeBFD)
}

// TestParseBFD attempts to parse a valid SCION/BFD packet.
// Compare to slayers_test.TestParseBFD where we attempt to parse the same
// packet while NOT linking against gopacket/layers.
func TestParseBFD(t *testing.T) {
	rawFile := filepath.Join(testdataDir, "scion-bfd.bin")
	raw, err := os.ReadFile(rawFile)
	if err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	pe := pkt.ErrorLayer()
	if pe != nil {
		require.NoError(t, pe.Error())
	}
	bfd := pkt.Layer(layers.LayerTypeBFD)
	require.NotNil(t, bfd)
	assert.IsType(t, &layers.BFD{}, bfd)
}

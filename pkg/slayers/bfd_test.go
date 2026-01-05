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

package slayers_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gopacket/gopacket"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/pkg/slayers"
)

// TestParseBFD attempts to parse a valid SCION/BFD when NOT linking against
// gopacket/layers, i.e. when LayerTypeBFD is not supported.
// Compare to slayers/internal/bfd_test.TestParseBFD where we parse the same
// packet while linking against gopacket/layers.
func TestParseBFD(t *testing.T) {
	rawFile := filepath.Join(goldenDir, "scion-bfd.bin")
	raw, err := os.ReadFile(rawFile)
	if err != nil {
		t.Fatal(err)
	}
	pkt := gopacket.NewPacket(raw, slayers.LayerTypeSCION, gopacket.Default)
	pe := pkt.ErrorLayer()
	require.NotNil(t, pe)
	require.EqualError(t, pe.Error(), "Layer type 122 has no associated decoder")
}

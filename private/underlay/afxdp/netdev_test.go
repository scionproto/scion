// Copyright 2026 SCION Association
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

//go:build linux && (amd64 || arm64)

package afxdp

import (
	"testing"

	"github.com/mdlayher/netlink"
	"github.com/stretchr/testify/require"

	"golang.org/x/sys/unix"
)

func TestParseGenlFamily(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.Uint16(unix.CTRL_ATTR_FAMILY_ID, 42)
	ae.Uint32(unix.CTRL_ATTR_VERSION, 7)
	attrs, err := ae.Encode()
	require.NoError(t, err)

	data := append([]byte{unix.CTRL_CMD_GETFAMILY, genlControlVersion, 0, 0}, attrs...)
	familyID, version, err := parseGenlFamily(data)
	require.NoError(t, err)
	require.Equal(t, uint16(42), familyID)
	require.Equal(t, uint8(7), version)
}

func TestParseNetdevXskFeaturesMessage(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.Uint64(netdevADevXskFeatures, netdevXskFlagsTxChecksum)
	attrs, err := ae.Encode()
	require.NoError(t, err)

	data := append([]byte{netdevCmdDevGet, 1, 0, 0}, attrs...)
	xskFeatures, err := parseNetdevXskFeaturesMessage(data)
	require.NoError(t, err)
	require.Equal(t, uint64(netdevXskFlagsTxChecksum), xskFeatures)
}

func TestParseNetdevXskFeaturesMessageMissingFeature(t *testing.T) {
	ae := netlink.NewAttributeEncoder()
	ae.Uint32(netdevADevIfindex, 3)
	attrs, err := ae.Encode()
	require.NoError(t, err)

	data := append([]byte{netdevCmdDevGet, 1, 0, 0}, attrs...)
	xskFeatures, err := parseNetdevXskFeaturesMessage(data)
	require.NoError(t, err)
	require.Zero(t, xskFeatures)
}

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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	genlControlVersion = 1

	netdevFamilyName = "netdev"

	netdevCmdDevGet = 1

	netdevADevIfindex     = 1
	netdevADevXskFeatures = 6

	netdevXskFlagsTxChecksum = 1 << 1
)

// queryTxChecksumOffload reports whether the kernel advertises AF_XDP TX checksum
// support for the given netdevice via the netdev generic-netlink family.
func queryTxChecksumOffload(ifIndex int) (bool, error) {
	conn, err := netlink.Dial(unix.NETLINK_GENERIC, nil)
	if err != nil {
		return false, fmt.Errorf("dialing generic netlink: %w", err)
	}
	defer conn.Close()

	familyID, familyVersion, err := lookupGenlFamily(conn, netdevFamilyName)
	if err != nil {
		return false, err
	}

	ae := netlink.NewAttributeEncoder()
	ae.Uint32(netdevADevIfindex, uint32(ifIndex))
	attrs, err := ae.Encode()
	if err != nil {
		return false, fmt.Errorf("encoding netdev request: %w", err)
	}

	msgs, err := conn.Execute(genlRequest(familyID, familyVersion, netdevCmdDevGet, attrs))
	if err != nil {
		return false, fmt.Errorf("querying netdev device info: %w", err)
	}

	xskFeatures, err := parseNetdevXskFeatures(msgs)
	if err != nil {
		return false, err
	}
	return xskFeatures&netdevXskFlagsTxChecksum != 0, nil
}

func lookupGenlFamily(conn *netlink.Conn, name string) (uint16, uint8, error) {
	ae := netlink.NewAttributeEncoder()
	ae.String(unix.CTRL_ATTR_FAMILY_NAME, name)
	attrs, err := ae.Encode()
	if err != nil {
		return 0, 0, fmt.Errorf("encoding control-family request: %w", err)
	}

	msgs, err := conn.Execute(genlRequest(unix.GENL_ID_CTRL, genlControlVersion, unix.CTRL_CMD_GETFAMILY, attrs))
	if err != nil {
		return 0, 0, fmt.Errorf("looking up generic-netlink family %q: %w", name, err)
	}

	if len(msgs) == 0 {
		return 0, 0, fmt.Errorf("looking up generic-netlink family %q: empty reply", name)
	}

	id, version, err := parseGenlFamily(msgs[0].Data)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing generic-netlink family %q: %w", name, err)
	}
	return id, version, nil
}

func genlRequest(familyID uint16, version, cmd uint8, attrs []byte) netlink.Message {
	data := make([]byte, unix.GENL_HDRLEN+len(attrs))
	data[0] = cmd
	data[1] = version
	copy(data[unix.GENL_HDRLEN:], attrs)
	return netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(familyID),
			Flags: netlink.Request,
		},
		Data: data,
	}
}

func parseGenlFamily(data []byte) (uint16, uint8, error) {
	if len(data) < unix.GENL_HDRLEN {
		return 0, 0, errors.New("short generic-netlink reply")
	}

	ad, err := netlink.NewAttributeDecoder(data[unix.GENL_HDRLEN:])
	if err != nil {
		return 0, 0, fmt.Errorf("decoding family attributes: %w", err)
	}

	var (
		familyID    uint16
		familyVer32 uint32
		haveID      bool
	)
	for ad.Next() {
		switch ad.Type() {
		case unix.CTRL_ATTR_FAMILY_ID:
			familyID = ad.Uint16()
			haveID = true
		case unix.CTRL_ATTR_VERSION:
			familyVer32 = ad.Uint32()
		}
	}
	if err := ad.Err(); err != nil {
		return 0, 0, fmt.Errorf("reading family attributes: %w", err)
	}
	if !haveID {
		return 0, 0, errors.New("generic-netlink family id missing")
	}

	familyVersion := uint8(familyVer32)
	if familyVersion == 0 {
		familyVersion = genlControlVersion
	}
	return familyID, familyVersion, nil
}

func parseNetdevXskFeatures(msgs []netlink.Message) (uint64, error) {
	if len(msgs) == 0 {
		return 0, errors.New("empty netdev reply")
	}
	return parseNetdevXskFeaturesMessage(msgs[0].Data)
}

func parseNetdevXskFeaturesMessage(data []byte) (uint64, error) {
	if len(data) < unix.GENL_HDRLEN {
		return 0, errors.New("short netdev reply")
	}

	ad, err := netlink.NewAttributeDecoder(data[unix.GENL_HDRLEN:])
	if err != nil {
		return 0, fmt.Errorf("decoding netdev attributes: %w", err)
	}
	ad.ByteOrder = binary.LittleEndian

	var xskFeatures uint64
	for ad.Next() {
		if ad.Type() == netdevADevXskFeatures {
			xskFeatures = ad.Uint64()
		}
	}
	if err := ad.Err(); err != nil {
		return 0, fmt.Errorf("reading netdev attributes: %w", err)
	}
	return xskFeatures, nil
}

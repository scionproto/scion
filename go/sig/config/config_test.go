// Copyright 2018 ETH Zurich
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

package config

import (
	"flag"
	"net"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	update = flag.Bool("update", false, "set to true to update reference testdata files")
)

func TestLoadFromFile(t *testing.T) {
	testCases := []struct {
		Name     string
		Err      error
		FileName string
		Config   Cfg
	}{
		{
			Name:     "simple",
			FileName: "01-loadfromfile",
			Err:      nil,
			Config: Cfg{
				ASes: map[addr.IA]*ASEntry{
					xtest.MustParseIA("1-ff00:0:1"): {
						Name: "AS 1",
						Nets: []*IPNet{
							{
								IP:   net.IP{192, 0, 2, 0},
								Mask: net.CIDRMask(24, 8*net.IPv4len),
							},
							{
								IP:   net.ParseIP("2001:DB8::"),
								Mask: net.CIDRMask(48, 8*net.IPv6len),
							},
						},
						Sigs: SIGSet{
							"remote-1": &SIG{
								Id:        "remote-1",
								Addr:      net.ParseIP("192.0.2.1"),
								CtrlPort:  1234,
								EncapPort: 5678,
							},
							"remote-2": &SIG{
								Id:        "remote-2",
								Addr:      net.ParseIP("192.0.2.2"),
								CtrlPort:  65535,
								EncapPort: 0,
							},
						},
					},
					xtest.MustParseIA("1-ff00:0:2"): {
						Nets: []*IPNet{
							{
								IP:   net.IP{203, 0, 113, 0},
								Mask: net.CIDRMask(24, 8*net.IPv4len),
							},
						},
						Sigs: SIGSet{},
					},
					xtest.MustParseIA("1-ff00:0:3"): {
						Nets: []*IPNet{},
						Sigs: SIGSet{},
					},
					xtest.MustParseIA("1-ff00:0:4"): {
						Name: "AS 4",
						Nets: []*IPNet{},
						Sigs: SIGSet{
							"remote-3": &SIG{
								Id:   "remote-3",
								Addr: net.ParseIP("2001:DB8::4"),
							},
						},
					},
				},
				ConfigVersion: 9001,
			},
		},
		{
			Name:     "verify fails for not network address",
			FileName: "01-not-network",
			Err: common.NewBasicError("Unable to parse SIG config",
				common.NewBasicError("Not a valid network, it refers to a host.", nil, "raw", "192.0.2.43/24")),
			Config: Cfg{
				ASes: map[addr.IA]*ASEntry{
					xtest.MustParseIA("1-ff00:0:1"): {
						Name: "AS 1",
						Nets: []*IPNet{
							{
								IP:   net.IP{192, 0, 2, 43},
								Mask: net.CIDRMask(24, 8*net.IPv4len),
							},
						},
					},
				},
				ConfigVersion: 9001,
			},
		},
	}

	Convey("Test SIG config marshal/unmarshal", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				if *update {
					xtest.MustMarshalJSONToFile(t, tc.Config, tc.FileName+".json")
				}

				cfg, err := LoadFromFile(filepath.Join("testdata", tc.FileName+".json"))
				SoMsg("err", err, ShouldResemble, tc.Err)
				if tc.Err == nil {
					SoMsg("cfg", *cfg, ShouldResemble, tc.Config)
				}
			})
		}
	})
}

func TestVerifyNetworkAddr(t *testing.T) {
	testCases := []struct {
		Name string
		Err  error
		CIDR string
	}{
		{
			Name: "Correct Network IPv4 Addr using 32 bits",
			Err:  nil,
			CIDR: "192.0.2.255/32",
		},
		{
			Name: "Correct Network IPv4 Addr using 0 bit",
			Err:  nil,
			CIDR: "0.0.0.0/0",
		},
		{
			Name: "Correct Network IPv4 Addr using 1 bit",
			Err:  nil,
			CIDR: "128.0.0.0/1",
		},
		{
			Name: "Invalid Network IPv4 Addr using 24 bit",
			Err:  common.NewBasicError("Not a valid network, it refers to a host.", nil, "raw", "10.0.0.55/24"),
			CIDR: "10.0.0.55/24",
		},

		{
			Name: "Correct Network IPv6 Addr using 128 bits",
			Err:  nil,
			CIDR: "2001:0db8:0123:4567:89ab:cdef:1234:5678/128",
		},
		{
			Name: "Correct Network IPv6 Addr using 0 bit",
			Err:  nil,
			CIDR: "::/0",
		},
		{
			Name: "Correct Network IPv6 Addr using 1 bit",
			Err:  nil,
			CIDR: "8000::/1",
		},
		{
			Name: "Invalid Network IPv6 Addr using 24 bit",
			Err:  common.NewBasicError("Not a valid network, it refers to a host.", nil, "raw", "2001::f1/24"),
			CIDR: "2001::f1/24",
		},
	}

	Convey("Test verify network addr in sig.json", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ip, ipnet, _ := net.ParseCIDR(tc.CIDR)
				err := verifyNetworkAddr(ip, *ipnet, tc.CIDR)
				SoMsg("err", err, ShouldResemble, tc.Err)
			})
		}
	})
}

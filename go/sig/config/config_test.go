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
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	update = flag.Bool("update", false, "set to true to update reference testdata files")
)

func TestLoadFromFile(t *testing.T) {
	testCases := []struct {
		Name     string
		FileName string
		Config   Cfg
	}{
		{
			Name:     "simple",
			FileName: "01-loadfromfile",
			Config: Cfg{
				ASes: map[addr.IA]*ASEntry{
					xtest.MustParseIA("1-ff00:0:1"): {
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
					},
					xtest.MustParseIA("1-ff00:0:2"): {
						Nets: []*IPNet{
							{
								IP:   net.IP{203, 0, 113, 0},
								Mask: net.CIDRMask(24, 8*net.IPv4len),
							},
						},
					},
					xtest.MustParseIA("1-ff00:0:3"): {
						Nets: []*IPNet{},
					},
					xtest.MustParseIA("1-ff00:0:4"): {
						Nets: []*IPNet{},
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
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cfg", *cfg, ShouldResemble, tc.Config)
			})
		}
	})
}

func TestIPNetUnmarshalJSON(t *testing.T) {
	testCases := []struct {
		Name  string
		Error bool
		JSON  string
	}{
		{
			Name:  "Correct Network IPv4 Addr using 32 bits",
			Error: false,
			JSON:  `"192.0.2.255/32"`,
		},
		{
			Name:  "Correct Network IPv4 Addr using 0 bit",
			Error: false,
			JSON:  `"0.0.0.0/0"`,
		},
		{
			Name:  "Correct Network IPv4 Addr using 1 bit",
			Error: false,
			JSON:  `"128.0.0.0/1"`,
		},
		{
			Name:  "Invalid Network IPv4 Addr using 24 bit",
			Error: true,
			JSON:  `"192.0.2.43/24"`,
		},
		{
			Name:  "Correct Network IPv6 Addr using 128 bits",
			Error: false,
			JSON:  `"2001:0db8:0123:4567:89ab:cdef:1234:5678/128"`,
		},
		{
			Name:  "Correct Network IPv6 Addr using 0 bit",
			Error: false,
			JSON:  `"::/0"`,
		},
		{
			Name:  "Correct Network IPv6 Addr using 1 bit",
			Error: false,
			JSON:  `"8000::/1"`,
		},
		{
			Name:  "Invalid Network IPv6 Addr using 24 bit",
			Error: true,
			JSON:  `"2001::f1/24"`,
		},
	}

	Convey("Test verify network addr in sig.json", t, func() {
		for _, tc := range testCases {
			Convey(tc.Name, func() {
				ipn := &IPNet{}
				err := ipn.UnmarshalJSON([]byte(tc.JSON))
				xtest.SoMsgError("err", err, tc.Error)
			})
		}
	})
}

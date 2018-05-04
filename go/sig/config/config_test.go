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

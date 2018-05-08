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

package pkicmn

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
)

const (
	ISD = addr.ISD(1)
)

var ases = []addr.AS{
	xtest.MustParseAS("ff00:0:10"),
	xtest.MustParseAS("ff00:0:11"),
	xtest.MustParseAS("ff00:0:20"),
	xtest.MustParseAS("ff00:0:21"),
	xtest.MustParseAS("ff00:0:30"),
	xtest.MustParseAS("ff00:0:31"),
}

type testStructure struct {
	scenario string
	selector string
	isdAsMap map[addr.ISD][]addr.IA
	err      string
}

func setupTest(t *testing.T) func() {
	// 1. Create a tmp dir which would be the RootDir
	dir, err := ioutil.TempDir("", "pkicmn")
	xtest.FailOnErr(t, err)
	RootDir = dir
	// 2. Create a folder for ISD named ISD1
	isdPath := filepath.Join(dir, fmt.Sprintf("ISD%d", ISD))
	err = os.Mkdir(isdPath, 0755)
	xtest.FailOnErr(t, err)
	// 3. Create folders for ASes inside ISD1
	for _, as := range ases {
		err = os.Mkdir(filepath.Join(isdPath, fmt.Sprintf("AS%s", as.FileFmt())), 0755)
		if err != nil {
			So(err, ShouldBeNil)
		}
	}
	return func() {
		os.RemoveAll(dir)
	}
}

func TestProcessSelector(t *testing.T) {
	Convey("Given root directory structure", t, func() {
		teardown := setupTest(t)
		tests := []testStructure{
			{
				scenario: "Empty selector string",
				selector: "",
				isdAsMap: nil,
				err:      ErrInvalidSelector,
			},
			{
				scenario: "ISD only selector with empty AS selector",
				selector: "1",
				isdAsMap: map[addr.ISD][]addr.IA{
					addr.ISD(1): getIAFromASes(addr.ISD(1), ases),
				},
				err: "",
			},
			{
				scenario: "ISD only selector with empty AS selector with wrong ISD",
				selector: "2",
				isdAsMap: nil,
				err:      ErrNoISDDirFound,
			},
			{
				scenario: "Wildcard ISD selector with empty AS selector",
				selector: "*",
				isdAsMap: map[addr.ISD][]addr.IA{
					addr.ISD(1): getIAFromASes(addr.ISD(1), ases),
				},
				err: "",
			},
			{
				scenario: "Wildcard ISD selector with non empty AS selector",
				selector: "*-ff00:0:10",
				isdAsMap: nil,
				err:      ErrInvalidSelector,
			},
			{
				scenario: "Wildcard AS selector with fixed ISD selector",
				selector: "1-*",
				isdAsMap: map[addr.ISD][]addr.IA{
					addr.ISD(1): getIAFromASes(addr.ISD(1), ases),
				},
				err: "",
			},
			{
				scenario: "Fixed ISD-AS selector",
				selector: "1-ff00:0:10",
				isdAsMap: map[addr.ISD][]addr.IA{
					addr.ISD(1): getIAFromASes(addr.ISD(1), ases[:1]),
				},
				err: "",
			},
			{
				scenario: "Fixed ISD-AS selector with wrong AS format",
				selector: "1-ff00_0_10",
				isdAsMap: nil,
				err:      ErrInvalidSelector,
			},
			{
				scenario: "Fixed ISD-AS selector with non-existent AS number",
				selector: "1-ff00:0:12",
				isdAsMap: nil,
				err:      ErrNoASDirFound,
			},
			{
				scenario: "Selector with more than one token",
				selector: "1-ff00:0:10-*",
				isdAsMap: nil,
				err:      ErrInvalidSelector,
			},
		}
		for _, test := range tests {
			Convey(test.scenario, func() {
				isdAsMap, err := ProcessSelector(test.selector)
				So(isdAsMap, ShouldResemble, test.isdAsMap)
				if test.err != "" {
					be := err.(common.BasicError)
					So(be.Msg, ShouldEqual, test.err)
				} else {
					So(err, ShouldBeNil)
				}
			})
		}
		Reset(func() {
			teardown()
		})
	})
}

func getIAFromASes(isd addr.ISD, asList []addr.AS) []addr.IA {
	var result []addr.IA
	for _, as := range asList {
		ia := addr.IA{
			I: isd,
			A: as,
		}
		result = append(result, ia)
	}
	return result
}

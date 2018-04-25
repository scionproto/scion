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
	ISD = "ISD1"
)

var ases = []string{"ASff00_0_10", "ASff00_0_11", "ASff00_0_20",
	"ASff00_0_21", "ASff00_0_30", "ASff00_0_31"}

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
	isdPath := filepath.Join(dir, ISD)
	err = os.Mkdir(isdPath, 0755)
	xtest.FailOnErr(t, err)
	// 3. Create folders for ASes inside ISD1
	for _, as := range ases {
		err = os.Mkdir(filepath.Join(isdPath, as), 0755)
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
					addr.ISD(1): getIAFromASes(addr.ISD(1), []string{ases[0]}),
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

func getIAFromASes(isd addr.ISD, asList []string) []addr.IA {
	var result []addr.IA
	for _, as := range asList {
		asFmt, err := addr.ASFromFileFmt(as, true)
		So(err, ShouldBeNil)
		ia := addr.IA{
			I: isd,
			A: asFmt,
		}
		result = append(result, ia)
	}
	return result
}

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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
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

func setupTest(t *testing.T) func() {
	// 1. Create a tmp dir which would be the RootDir
	dir, err := ioutil.TempDir("", "pkicmn")
	require.NoError(t, err)
	RootDir = dir
	// 2. Create a folder for ISD named ISD1
	isdPath := filepath.Join(dir, fmt.Sprintf("ISD%d", ISD))
	err = os.Mkdir(isdPath, 0755)
	require.NoError(t, err)
	// 3. Create folders for ASes inside ISD1
	for _, as := range ases {
		err = os.Mkdir(filepath.Join(isdPath, fmt.Sprintf("AS%s", as.FileFmt())), 0755)
		require.NoError(t, err)
	}
	return func() {
		os.RemoveAll(dir)
	}
}

func TestProcessSelector(t *testing.T) {
	setupTest(t)
	tests := map[string]struct {
		selector string
		isdAsMap map[addr.ISD][]addr.IA
		err      error
	}{
		"Empty selector string": {
			err: ErrInvalidSelector,
		},
		"ISD only selector with empty AS selector": {
			selector: "1",
			isdAsMap: map[addr.ISD][]addr.IA{
				addr.ISD(1): getIAFromASes(addr.ISD(1), ases),
			},
		},
		"ISD only selector with empty AS selector with wrong ISD": {
			selector: "2",
			err:      ErrNoISDDirFound,
		},
		"Wildcard ISD selector with empty AS selector": {
			selector: "*",
			isdAsMap: map[addr.ISD][]addr.IA{
				addr.ISD(1): getIAFromASes(addr.ISD(1), ases),
			},
		},
		"Wildcard ISD selector with non empty AS selector": {
			selector: "*-ff00:0:10",
			err:      ErrInvalidSelector,
		},
		"Wildcard AS selector with fixed ISD selector": {
			selector: "1-*",
			isdAsMap: map[addr.ISD][]addr.IA{
				addr.ISD(1): getIAFromASes(addr.ISD(1), ases),
			},
		},
		"Fixed ISD-AS selector": {
			selector: "1-ff00:0:10",
			isdAsMap: map[addr.ISD][]addr.IA{
				addr.ISD(1): getIAFromASes(addr.ISD(1), ases[:1]),
			},
		},
		"Fixed ISD-AS selector with wrong AS format": {
			selector: "1-ff00_0_10",
			err:      ErrInvalidSelector,
		},
		"Fixed ISD-AS selector with non-existent AS number": {
			selector: "1-ff00:0:12",
			err:      ErrNoASDirFound,
		},
		"Selector with more than one token": {
			selector: "1-ff00:0:10-*",
			err:      ErrInvalidSelector,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			isdAsMap, err := ProcessSelector(test.selector)
			assert.Equal(t, test.isdAsMap, isdAsMap)
			xtest.AssertErrorsIs(t, err, test.err)
		})
	}
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

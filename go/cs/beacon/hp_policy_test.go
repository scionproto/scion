// Copyright 2019 ETH Zurich
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

package beacon_test

import (
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/cs/beacon"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/hiddenpath"
	"github.com/scionproto/scion/go/lib/hiddenpath/hiddenpathtest"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	id69b5 = hiddenpathtest.MustParseHPGroupId("ff00:0:110-69b5")
	idabcd = hiddenpathtest.MustParseHPGroupId("ffaa:0:222-abcd")
)

var refPolicy = beacon.RegPolicy{
	RegUp:         true,
	RegDown:       true,
	MaxExpiration: util.DurWrap{Duration: time.Hour},
}

// expected is the HPRegistration which should result from parsing 'testdata/hp_policy.yml'
// It is missing the initialized hiddenpath.Groups (unmarshalling those is tested in the hiddenpath
// package)
var expected = &beacon.HPRegistration{
	HPPolicies: beacon.HPPolicies{
		DefaultAction:   "register",
		HiddenAndPublic: true,
		Policies: map[common.IFIDType]beacon.HPPolicy{
			2: {
				Public: refPolicy,
				Hidden: map[hiddenpath.GroupId]beacon.RegPolicy{
					id69b5: refPolicy,
					idabcd: refPolicy,
				},
			},
			3: {
				Public: refPolicy,
			},
		},
	},
	HPGroups: map[hiddenpath.GroupId]*beacon.HPGroup{
		id69b5: {
			GroupCfgPath: "testdata/HPGCfg_ff00_0_110-69b5.json",
		},
		idabcd: {
			GroupCfgPath: "testdata/HPGCfg_ffaa_0_222-abcd.json",
		},
	},
}

func TestHPRegistrationFromYaml(t *testing.T) {

	t.Run("Valid", func(t *testing.T) {
		fn := "testdata/hp_policy.yml"
		r, err := beacon.LoadHPRegFromYaml(fn)
		require.NoError(t, err)

		for _, v := range r.HPGroups {
			assert.NotZero(t, v.Group, "HPGroup %q not initialized", v.GroupCfgPath)
			v.Group = hiddenpath.Group{}
		}
		assert.Equal(t, expected, r)
	})

	t.Run("Unavailable group", func(t *testing.T) {
		b, err := ioutil.ReadFile("testdata/hp_policy.yml")
		require.NoError(t, err)

		modified := strings.Replace(string(b), "ff00:0:110-69b5", "ff00:0:0-0", 1)
		_, err = beacon.ParseHPRegYaml([]byte(modified))
		assert.EqualError(t, err,
			`Policy references unavailable Group GroupId="ff00:0:110-69b5"`)
	})

	t.Run("Load wrong group", func(t *testing.T) {
		b, err := ioutil.ReadFile("testdata/hp_policy.yml")
		require.NoError(t, err)

		modified := strings.Replace(string(b), "ff00_0_110-69b5", "ffaa_0_222-abcd", 1)
		_, err = beacon.ParseHPRegYaml([]byte(modified))
		assert.EqualError(t, err, `GroupId key doesn't match loaded `+
			`HPGroup key="ff00:0:110-69b5" loaded="ffaa:0:222-abcd"`)
	})
}

// Copyright 2020 Anapaya Systems
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

package control_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/gateway/control"
	"github.com/scionproto/scion/gateway/pktcls"
	"github.com/scionproto/scion/gateway/routing"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/xtest"
)

func TestConfigPublisherSubscribeSessionPolicies(t *testing.T) {
	n := control.ConfigPublisher{}
	c := n.SubscribeSessionPolicies()
	assert.Empty(t, c, "channel must be unbuffered")
}

func TestConfigPublisherSubscribeRemoteIAs(t *testing.T) {
	n := control.ConfigPublisher{}
	c := n.SubscribeRemoteIAs()
	assert.Empty(t, c, "channel must be unbuffered")
}

func TestConfigPublisherPublish(t *testing.T) {
	expectedSP := control.SessionPolicies{
		{
			IA:             addr.MustParseIA("1-ff00:0:110"),
			TrafficMatcher: pktcls.CondTrue,
			PerfPolicy:     dummyPerfPolicy{},
			PathPolicy:     control.DefaultPathPolicy,
			PathCount:      1,
			Prefixes:       xtest.MustParseCIDRs(t, "127.0.0.0/8"),
		},
	}
	testCases := map[string]func(*testing.T){
		"publish session pol no subsribers": func(t *testing.T) {
			n := control.ConfigPublisher{}
			doneCh := make(chan struct{})
			go func() {
				n.Publish(expectedSP, nil)
				close(doneCh)
			}()
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
		"publish routing pol with blocking sp subscribers": func(t *testing.T) {
			rp := &routing.Policy{DefaultAction: routing.Reject}
			n := control.ConfigPublisher{}
			n.SubscribeRemoteIAs()
			n.SubscribeSessionPolicies()
			doneCh := make(chan struct{})
			go func() {
				n.Publish(nil, rp)
				close(doneCh)
			}()
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
			assert.Equal(t, rp, n.RoutingPolicy())
			assert.NotSame(t, rp, n.RoutingPolicy())
		},
		"publish notifies SP subscribers": func(t *testing.T) {
			n := control.ConfigPublisher{}
			sps1 := n.SubscribeSessionPolicies()
			sps2 := n.SubscribeSessionPolicies()
			ias1 := n.SubscribeRemoteIAs()
			ias2 := n.SubscribeRemoteIAs()
			doneCh := make(chan struct{})
			go func() {
				// wait on sps2 first to check for HOL blocking.
				actual := <-sps2
				assert.Equal(t, expectedSP, actual)
				actual[0].PathCount = 5
				assert.NotEqual(t, expectedSP, actual)
				actual = <-sps1
				assert.Equal(t, expectedSP, actual)
				actual[0].PathCount = 5
				assert.NotEqual(t, expectedSP, actual)
			}()
			go func() {
				// wait on ias2 first to check for HOL blocking.
				actual := <-ias2
				assert.Equal(t, []addr.IA{addr.MustParseIA("1-ff00:0:110")}, actual)
				actual = <-ias1
				assert.Equal(t, []addr.IA{addr.MustParseIA("1-ff00:0:110")}, actual)
			}()
			go func() {
				n.Publish(expectedSP, nil)
				close(doneCh)
			}()
			xtest.AssertReadReturnsBefore(t, doneCh, time.Second)
		},
	}
	for name, tc := range testCases {
		t.Run(name, tc)
	}
}

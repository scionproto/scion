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

package routing_test

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/pkg/gateway/routing"
)

func TestAdvertiseList(t *testing.T) {
	from := addr.IA{I: 1}
	to := addr.IA{I: 2}

	policy := routing.Policy{DefaultAction: routing.Reject}

	assert.Empty(t, routing.AdvertiseList(nil, from, to))
	assert.Empty(t, routing.AdvertiseList(&policy, from, to))

	policy.Rules = append(policy.Rules, routing.Rule{
		Action:  routing.Advertise,
		From:    routing.NewIAMatcher(t, "1-0"),
		To:      routing.NewIAMatcher(t, "2-0"),
		Network: routing.NewNetworkMatcher(t, "127.1.0.0/30,10.0.0.0/16"),
	})
	policy.Rules = append(policy.Rules, routing.Rule{
		Action:  routing.Advertise,
		From:    routing.NewIAMatcher(t, "2-0"),
		To:      routing.NewIAMatcher(t, "1-0"),
		Network: routing.NewNetworkMatcher(t, "!127.1.0.0/30"),
	})
	assert.ElementsMatch(t, []*net.IPNet{
		{IP: net.ParseIP("127.1.0.0").To4(), Mask: net.CIDRMask(30, 32)},
		{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(16, 32)},
	}, routing.AdvertiseList(&policy, from, to))
	assert.Empty(t, routing.AdvertiseList(&policy, to, from))
}

func TestRedistributeBGPList(t *testing.T) {
	from := addr.IA{I: 1}
	to := addr.IA{I: 2}

	policy := routing.Policy{DefaultAction: routing.Reject}

	assert.Empty(t, routing.AdvertiseList(nil, from, to))
	assert.Empty(t, routing.AllowedPrefixesBGP(&policy, from, to))

	policy.Rules = append(policy.Rules, routing.Rule{
		Action:  routing.RedistributeBGP,
		From:    routing.NewIAMatcher(t, "1-0"),
		To:      routing.NewIAMatcher(t, "2-0"),
		Network: routing.NewNetworkMatcher(t, "127.1.0.0/30,10.0.0.0/16"),
	})
	policy.Rules = append(policy.Rules, routing.Rule{
		Action:  routing.RedistributeBGP,
		From:    routing.NewIAMatcher(t, "2-0"),
		To:      routing.NewIAMatcher(t, "1-0"),
		Network: routing.NewNetworkMatcher(t, "!127.1.0.0/30"),
	})
	assert.ElementsMatch(t, []*net.IPNet{
		{IP: net.ParseIP("127.1.0.0").To4(), Mask: net.CIDRMask(30, 32)},
		{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(16, 32)},
	}, routing.AllowedPrefixesBGP(&policy, from, to))
	assert.Empty(t, routing.AllowedPrefixesBGP(&policy, to, from))
}

func TestStaticAdvertiseList(t *testing.T) {
	policy := routing.Policy{DefaultAction: routing.Reject}

	assert.Empty(t, routing.StaticAdvertised(nil))
	assert.Empty(t, routing.StaticAdvertised(&policy))

	policy.Rules = append(policy.Rules, routing.Rule{
		Action:  routing.Advertise,
		From:    routing.NewIAMatcher(t, "1-0"),
		To:      routing.NewIAMatcher(t, "2-0"),
		Network: routing.NewNetworkMatcher(t, "127.1.0.0/30,10.0.0.0/16"),
	})
	policy.Rules = append(policy.Rules, routing.Rule{
		Action:  routing.Accept,
		From:    routing.NewIAMatcher(t, "2-0"),
		To:      routing.NewIAMatcher(t, "1-0"),
		Network: routing.NewNetworkMatcher(t, "!127.1.0.0/30"),
	})
	assert.ElementsMatch(t, []*net.IPNet{
		{IP: net.ParseIP("127.1.0.0").To4(), Mask: net.CIDRMask(30, 32)},
		{IP: net.ParseIP("10.0.0.0").To4(), Mask: net.CIDRMask(16, 32)},
	}, routing.StaticAdvertised(&policy))
}

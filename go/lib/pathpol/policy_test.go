// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

package pathpol

import (
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/lib/xtest/graph"
)

func TestBasicPolicy(t *testing.T) {
	tests := map[string]struct {
		Name       string
		Policy     *Policy
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		"Empty policy": {
			Policy:     &Policy{},
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			paths := pp.GetPaths(test.Src, test.Dst)
			outPaths := test.Policy.Filter(paths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}

func TestOptionsEval(t *testing.T) {
	tests := map[string]struct {
		Policy     *Policy
		Src        addr.IA
		Dst        addr.IA
		ExpPathNum int
	}{
		"one option, allow everything": {
			Policy: NewPolicy("", nil, nil, []Option{
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
								denyEntry,
							},
						},
					},
					Weight: 0,
				},
			}),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"two options, deny everything": {
			Policy: NewPolicy("", nil, nil, []Option{
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
								denyEntry,
							},
						},
					},
					Weight: 0,
				},
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Deny, Rule: mustHopPredicate(t, "0-0#0")},
								denyEntry,
							},
						},
					},
					Weight: 1,
				},
			}),
			Src:        xtest.MustParseIA("2-ff00:0:212"),
			Dst:        xtest.MustParseIA("2-ff00:0:211"),
			ExpPathNum: 2,
		},
		"two options, first: allow everything, second: allow one path": {
			Policy: NewPolicy("", nil, nil, []Option{
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
								denyEntry,
							},
						},
					},
					Weight: 0,
				},
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:110#0")},
								{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
								{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:111#2823")},
								allowEntry,
							},
						},
					},
					Weight: 1,
				},
			}),
			Src:        xtest.MustParseIA("1-ff00:0:122"),
			Dst:        xtest.MustParseIA("2-ff00:0:222"),
			ExpPathNum: 1,
		},
		"two options, combined": {
			Policy: NewPolicy("", nil, nil, []Option{
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
								allowEntry,
							},
						},
					},
					Weight: 0,
				},
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Deny, Rule: mustHopPredicate(t, "2-ff00:0:210#0")},
								allowEntry,
							},
						},
					},
					Weight: 0,
				},
			}),
			Src:        xtest.MustParseIA("1-ff00:0:110"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 3,
		},
		"two options, take first": {
			Policy: NewPolicy("", nil, nil, []Option{
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
								allowEntry,
							},
						},
					},
					Weight: 1,
				},
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Deny, Rule: mustHopPredicate(t, "2-ff00:0:210#0")},
								allowEntry,
							},
						},
					},
					Weight: 0,
				},
			}),
			Src:        xtest.MustParseIA("1-ff00:0:110"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 1,
		},
		"two options, take second": {
			Policy: NewPolicy("", nil, nil, []Option{
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Deny, Rule: mustHopPredicate(t, "1-ff00:0:120#0")},
								allowEntry},
						},
					},
					Weight: 1,
				},
				{
					Policy: &Policy{
						ACL: &ACL{
							Entries: []*ACLEntry{
								{Action: Deny, Rule: mustHopPredicate(t, "2-ff00:0:210#0")},
								allowEntry},
						},
					},
					Weight: 10,
				},
			}),
			Src:        xtest.MustParseIA("1-ff00:0:110"),
			Dst:        xtest.MustParseIA("2-ff00:0:220"),
			ExpPathNum: 2,
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			paths := pp.GetPaths(test.Src, test.Dst)
			outPaths := test.Policy.Filter(paths)
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}

func TestPolicyFromExtPolicy(t *testing.T) {
	tests := map[string]struct {
		Policy         *ExtPolicy
		Extended       []*ExtPolicy
		ResolvedPolicy *Policy
	}{
		"one extends, use sub acl": {
			Policy: &ExtPolicy{
				Extends: []string{"policy1"},
			},
			Extended: []*ExtPolicy{
				{
					Name: "policy1",
					ACL: &ACL{
						Entries: []*ACLEntry{
							{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
							denyEntry,
						},
					},
				},
			},
			ResolvedPolicy: &Policy{
				ACL: &ACL{
					Entries: []*ACLEntry{
						{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
						denyEntry,
					},
				},
			},
		},
		"use option of extended policy": {
			Policy: &ExtPolicy{
				Extends: []string{"policy1"},
			},
			Extended: []*ExtPolicy{
				{
					Name: "policy1",
					Options: []ExtOption{
						{
							Weight: 1,
							Policy: &ExtPolicy{
								ACL: &ACL{
									Entries: []*ACLEntry{
										{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
										denyEntry,
									},
								},
							},
						},
					},
				},
			},
			ResolvedPolicy: &Policy{
				Options: []Option{
					{
						Weight: 1,
						Policy: &Policy{
							ACL: &ACL{
								Entries: []*ACLEntry{
									{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
									denyEntry,
								},
							},
						},
					},
				},
			},
		},
		"two extends, use sub acl and list": {
			Policy: &ExtPolicy{Extends: []string{"policy1"}},
			Extended: []*ExtPolicy{
				{
					Name: "policy1",
					ACL: &ACL{
						Entries: []*ACLEntry{
							{
								Action: Allow,
								Rule:   mustHopPredicate(t, "0-0#0"),
							},
							denyEntry,
						},
					},
					Sequence: newSequence(t, "1-ff00:0:133#1019 1-ff00:0:132#1910"),
				},
			},
			ResolvedPolicy: &Policy{
				ACL: &ACL{
					Entries: []*ACLEntry{
						{
							Action: Allow,
							Rule:   mustHopPredicate(t, "0-0#0"),
						},
						denyEntry,
					},
				},
				Sequence: newSequence(t, "1-ff00:0:133#1019 1-ff00:0:132#1910"),
			},
		},
		"two extends, only use acl": {
			Policy: &ExtPolicy{
				Sequence: newSequence(t, "1-ff00:0:133#0 1-ff00:0:132#0"),
				Extends:  []string{"policy2"},
			},
			Extended: []*ExtPolicy{
				{
					Name: "policy2",
					ACL: &ACL{
						Entries: []*ACLEntry{
							{
								Action: Allow,
								Rule:   mustHopPredicate(t, "0-0#0")},
							denyEntry,
						},
					},
				},
				{
					Name:     "policy1",
					Sequence: newSequence(t, "1-ff00:0:133#1019 1-ff00:0:132#1910"),
				},
			},
			ResolvedPolicy: &Policy{
				ACL: &ACL{
					Entries: []*ACLEntry{
						{Action: Allow, Rule: mustHopPredicate(t, "0-0#0")},
						denyEntry,
					},
				},
				Sequence: newSequence(t, "1-ff00:0:133#0 1-ff00:0:132#0"),
			},
		},
		"three extends, use last list": {
			Policy: &ExtPolicy{
				Extends: []string{"p1", "p2", "p3"},
			},
			Extended: []*ExtPolicy{
				{
					Name:     "p1",
					Sequence: newSequence(t, "1-ff00:0:133#1011 1-ff00:0:132#1911"),
				},
				{
					Name:     "p2",
					Sequence: newSequence(t, "1-ff00:0:133#1012 1-ff00:0:132#1912"),
				},
				{
					Name:     "p3",
					Sequence: newSequence(t, "1-ff00:0:133#1013 1-ff00:0:132#1913"),
				},
			},
			ResolvedPolicy: &Policy{
				Sequence: newSequence(t, "1-ff00:0:133#1013 1-ff00:0:132#1913"),
			},
		},
		"nested extends": {
			Policy: &ExtPolicy{
				Extends: []string{"policy1"},
			},
			Extended: []*ExtPolicy{
				{
					Name:    "policy1",
					Extends: []string{"policy2"},
				},
				{
					Name:    "policy2",
					Extends: []string{"policy3"},
				},
				{
					Name:     "policy3",
					Sequence: newSequence(t, "1-ff00:0:133#1011 1-ff00:0:132#1911"),
				},
			},
			ResolvedPolicy: &Policy{
				Sequence: newSequence(t, "1-ff00:0:133#1011 1-ff00:0:132#1911"),
			},
		},
		"nested extends, evaluating order": {
			Policy: &ExtPolicy{
				Extends: []string{"policy3"},
			},
			Extended: []*ExtPolicy{
				{
					Name:     "policy3",
					Sequence: newSequence(t, "1-ff00:0:133#1010 1-ff00:0:132#1910"),
					Extends:  []string{"policy2"},
				},
				{
					Name:    "policy2",
					Extends: []string{"policy1"},
				},
				{
					Name:     "policy1",
					Sequence: newSequence(t, "1-ff00:0:133#1011 1-ff00:0:132#1911"),
				},
			},
			ResolvedPolicy: &Policy{
				Sequence: newSequence(t, "1-ff00:0:133#1010 1-ff00:0:132#1910"),
			},
		},
		"different nested extends, evaluating order": {
			Policy: &ExtPolicy{
				Extends: []string{"policy6"},
			},
			Extended: []*ExtPolicy{
				{
					Name:     "policy3",
					Sequence: newSequence(t, "1-ff00:0:133#1010 1-ff00:0:132#1910"),
					Extends:  []string{"policy2"},
				},
				{
					Name:    "policy2",
					Extends: []string{"policy1"},
				},
				{
					Name:    "policy6",
					Extends: []string{"policy3"},
				},
				{
					Name:     "policy1",
					Sequence: newSequence(t, "1-ff00:0:133#1011 1-ff00:0:132#1911"),
				},
			},
			ResolvedPolicy: &Policy{
				Sequence: newSequence(t, "1-ff00:0:133#1010 1-ff00:0:132#1910"),
			},
		},
		"options with extended": {
			Policy: &ExtPolicy{
				Options: []ExtOption{
					{
						Weight: 1,
						Policy: &ExtPolicy{Extends: []string{"policy1"}},
					},
				},
			},
			Extended: []*ExtPolicy{
				{
					Name:    "policy1",
					Extends: []string{"policy2"},
				},
				{
					Name:    "policy2",
					Extends: []string{"policy3"},
				},
				{
					Name:     "policy3",
					Sequence: newSequence(t, "1-ff00:0:133#1011 1-ff00:0:132#1911"),
				},
			},
			ResolvedPolicy: &Policy{
				Options: []Option{
					{
						Weight: 1,
						Policy: &Policy{
							Sequence: newSequence(t, "1-ff00:0:133#1011 1-ff00:0:132#1911"),
						},
					},
				},
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pol, err := PolicyFromExtPolicy(test.Policy, test.Extended)
			if assert.NoError(t, err) {
				assert.Equal(t, test.ResolvedPolicy, pol)
			}
		})
	}

	t.Run("TestPolicy Extend not found", func(t *testing.T) {
		extPolicy := &ExtPolicy{Extends: []string{"policy1"}}
		extended := []*ExtPolicy{
			{
				Name:    "policy1",
				Extends: []string{"policy16"},
			},
			{
				Name:    "policy2",
				Extends: []string{"policy3"},
			},
			{
				Name:     "policy3",
				Sequence: newSequence(t, "1-ff00:0:133#1011 1-ff00:0:132#1911"),
			},
		}
		_, err := PolicyFromExtPolicy(extPolicy, extended)
		assert.Error(t, err)
	})
}

func TestFilterOpt(t *testing.T) {
	tests := map[string]struct {
		Policy     *Policy
		ExpPathNum int
	}{
		"sequence in options is ignored": {
			Policy: NewPolicy("", nil, nil, []Option{
				{
					Policy: &Policy{
						Sequence: newSequence(t, "0+ 1-ff00:0:111 0+"),
					},
					Weight: 0,
				},
			}),
			ExpPathNum: 3,
		},
		"sequence is ignored": {
			Policy:     NewPolicy("", nil, newSequence(t, "0+ 1-ff00:0:111 0+"), nil),
			ExpPathNum: 3,
		},
	}
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	pp := NewPathProvider(ctrl)
	src := xtest.MustParseIA("1-ff00:0:110")
	dst := xtest.MustParseIA("2-ff00:0:220")
	paths := pp.GetPaths(src, dst)
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			outPaths := test.Policy.FilterOpt(paths, FilterOptions{IgnoreSequence: true})
			assert.Equal(t, test.ExpPathNum, len(outPaths))
		})
	}
}

func newSequence(t *testing.T, str string) *Sequence {
	seq, err := NewSequence(str)
	xtest.FailOnErr(t, err)
	return seq
}

type PathProvider struct {
	g *graph.Graph
}

func NewPathProvider(ctrl *gomock.Controller) PathProvider {
	return PathProvider{
		g: graph.NewDefaultGraph(ctrl),
	}
}

func (p PathProvider) GetPaths(src, dst addr.IA) PathSet {
	result := make(PathSet)
	paths := p.g.GetPaths(src.String(), dst.String())
	for _, ifids := range paths {
		pathIntfs := make([]PathInterface, 0, len(ifids))
		var key strings.Builder
		for _, ifid := range ifids {
			ia := p.g.GetParent(ifid)
			pathIntfs = append(pathIntfs, testPathIntf{ia: ia, ifid: ifid})
			key.WriteString(fmt.Sprintf("%s-%d", ia, ifid))
		}
		result[key.String()] = &testPath{interfaces: pathIntfs, key: key.String()}
	}
	return result
}

type testPath struct {
	interfaces []PathInterface
	key        string
}

func (p *testPath) Interfaces() []PathInterface {
	return p.interfaces
}

func (p *testPath) Key() string { return p.key }

type testPathIntf struct {
	ia   addr.IA
	ifid common.IFIDType
}

func (i testPathIntf) IfId() common.IFIDType { return i.ifid }
func (i testPathIntf) IA() addr.IA           { return i.ia }

func mustHopPredicate(t *testing.T, str string) *HopPredicate {
	hp, err := HopPredicateFromString(str)
	xtest.FailOnErr(t, err)
	return hp
}

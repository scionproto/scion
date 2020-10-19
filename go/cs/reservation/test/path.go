// Copyright 2020 ETH Zurich, Anapaya Systems
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

package test

import (
	base "github.com/scionproto/scion/go/cs/reservation"
)

type TestColibriPath struct {
	HopCount   int
	CurrentHop int
	Ingress    uint16
	Egress     uint16
}

var _ base.ColibriPath = (*TestColibriPath)(nil)

func (p *TestColibriPath) Copy() base.ColibriPath {
	return p
}

func (p *TestColibriPath) Reverse() error {
	return nil
}

func (p *TestColibriPath) NumberOfHops() int {
	return p.HopCount
}

func (p *TestColibriPath) IndexOfCurrentHop() int {
	return p.CurrentHop
}

func (p *TestColibriPath) IngressEgressIFIDs() (uint16, uint16) {
	return p.Ingress, p.Egress
}

// NewTestPath returns a new path with one segment consisting on 3 hopfields: (0,2)->(1,2)->(1,0).
func NewTestPath() base.ColibriPath {
	path := TestColibriPath{
		Ingress: 1,
		Egress:  2,
	}
	return &path
}

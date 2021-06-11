// Copyright 2019 Anapaya Systems
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

package snet

import (
	"net"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/slayers"
)

var NewScionConnWriter = newScionConnWriter

func NewScionConnBase(localIA addr.IA, listen *net.UDPAddr) *scionConnBase {
	return &scionConnBase{
		listen:   listen,
		scionNet: &SCIONNetwork{LocalIA: localIA},
	}
}

func SCMPParameterProblemWithCode(m SCMPParameterProblem, c slayers.SCMPCode) SCMPParameterProblem {
	m.code = c
	return m
}

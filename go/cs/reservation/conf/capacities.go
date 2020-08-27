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

package conf

import (
	"encoding/json"
	"sort"

	base "github.com/scionproto/scion/go/cs/reservation"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/serrors"
)

// internal structure used to serialize to and from json.
type capacities struct {
	// ingress capacities
	CapIn map[common.IFIDType]uint64 `json:"ingress_kbps"`
	// egress capacities
	CapEg map[common.IFIDType]uint64 `json:"egress_kbps"`
	// configured allowed transit
	In2Eg map[common.IFIDType]map[common.IFIDType]uint64 `json:"ingress_to_egress_kbps"`
}

// Capacities aka capacity matrix.
type Capacities struct {
	c capacities
	// derived fields from the above ones:
	inIfs []common.IFIDType
	egIfs []common.IFIDType
}

var _ base.Capacities = (*Capacities)(nil)
var _ json.Unmarshaler = (*Capacities)(nil)
var _ json.Marshaler = (*Capacities)(nil)

func (c *Capacities) IngressInterfaces() []common.IFIDType           { return c.inIfs }
func (c *Capacities) EgressInterfaces() []common.IFIDType            { return c.egIfs }
func (c *Capacities) Capacity(from, to common.IFIDType) uint64       { return c.c.In2Eg[from][to] }
func (c *Capacities) CapacityIngress(ingress common.IFIDType) uint64 { return c.c.CapIn[ingress] }
func (c *Capacities) CapacityEgress(egress common.IFIDType) uint64   { return c.c.CapEg[egress] }

// UnmarshalJSON deserializes into the json-aware internal data structure.
func (c *Capacities) UnmarshalJSON(b []byte) error {
	if err := json.Unmarshal(b, &c.c); err != nil {
		return err
	}
	return c.init()
}

// MarshalJSON serializes the internal json-friendly structure.
func (c Capacities) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.c)
}

func (c *Capacities) init() error {
	totalEgress := make(map[common.IFIDType]uint64)
	for ingress, intoMap := range c.c.In2Eg {
		var accumIngress uint64
		for egress, cap := range intoMap {
			accumIngress += cap
			totalEgress[egress] += cap
			if egress == ingress && cap != 0 {
				return serrors.New("capacity is inconsistent, ingress to itself not zero",
					"ingress", ingress)
			}
		}
		if _, found := c.c.CapIn[ingress]; !found {
			return serrors.New("capacity is inconsistent, must declare ingress capacity",
				"ingress", ingress)
		}
		if accumIngress > c.c.CapIn[ingress] {
			return serrors.New("capacity is inconsistent, ingress accum too high", "ingress",
				ingress, "ingress_accum", accumIngress, "ingress_declared", c.c.CapIn[ingress])
		}
	}
	for egress, accum := range totalEgress {
		if _, found := c.c.CapEg[egress]; !found {
			return serrors.New("capacity is inconsistent, must declare egress capacity",
				"egress", egress)
		}
		if accum > c.c.CapEg[egress] {
			return serrors.New("capacity is inconsistent, egress accum too high", "egress", egress,
				"egress_accum", accum, "egress_declared", c.c.CapEg[egress])
		}
	}
	// init list of ingress interfaces
	c.inIfs = make([]common.IFIDType, len(c.c.CapIn))
	i := 0
	for ifid := range c.c.CapIn {
		c.inIfs[i] = ifid
		i++
	}
	// init list of egress interfaces
	c.egIfs = make([]common.IFIDType, len(c.c.CapEg))
	i = 0
	for ifid := range c.c.CapEg {
		c.egIfs[i] = ifid
		i++
	}
	// sort them just to simplify debugging
	sort.Slice(c.inIfs, func(i, j int) bool { return c.inIfs[i] < c.inIfs[j] })
	sort.Slice(c.egIfs, func(i, j int) bool { return c.egIfs[i] < c.egIfs[j] })

	return nil
}

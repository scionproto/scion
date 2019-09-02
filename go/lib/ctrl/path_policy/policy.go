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

package path_policy

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/proto"
)

var _ proto.Cerealizable = (*Policy)(nil)

// Policy is the high level capnp msg representation for policies.
type Policy struct {
	ACL      *ACL
	Sequence string
	Options  []Option
}

func (p *Policy) ProtoId() proto.ProtoIdType {
	return proto.Policy_TypeID
}

func (p *Policy) String() string {
	return fmt.Sprintf("{ACL: %s, Sequence: %s, Options: %v}",
		p.ACL, p.Sequence, p.Options)
}

// Copy deep copies policy.
func (p *Policy) Copy() *Policy {
	if p == nil {
		return nil
	}
	return &Policy{
		ACL:      p.ACL.Copy(),
		Sequence: p.Sequence,
		Options:  copyOptions(p.Options),
	}
}

var _ proto.Cerealizable = (*ExtPolicy)(nil)

type ExtPolicy struct {
	Extends []string
	*Policy
}

func (p *ExtPolicy) ProtoId() proto.ProtoIdType {
	return proto.ExtPolicy_TypeID
}

func (p *ExtPolicy) String() string {
	return fmt.Sprintf("{Extends: %v, Policy: %s}", p.Extends, p.Policy)
}

func (p *ExtPolicy) Copy() *ExtPolicy {
	if p == nil {
		return nil
	}
	return &ExtPolicy{
		Extends: append([]string{}, p.Extends...),
		Policy:  p.Policy.Copy(),
	}
}

var _ proto.Cerealizable = (*Option)(nil)

type Option struct {
	Weight int
	Policy *ExtPolicy
}

func (o *Option) ProtoId() proto.ProtoIdType {
	return proto.Option_TypeID
}

func (o *Option) String() string {
	return fmt.Sprintf("{Weight: %d, Policy: %s}", o.Weight, o.Policy)
}

var _ proto.Cerealizable = (*ACL)(nil)

type ACL struct {
	Entries []*ACLEntry
}

func (a *ACL) ProtoId() proto.ProtoIdType {
	return proto.ACL_TypeID
}

func (a *ACL) String() string {
	return fmt.Sprintf("{Entries: %v}", a.Entries)
}

func (a *ACL) Copy() *ACL {
	if a == nil {
		return nil
	}
	return &ACL{
		Entries: copyEntries(a.Entries),
	}
}

var _ proto.Cerealizable = (*ACLEntry)(nil)

type ACLEntry struct {
	Action proto.ACLAction
	Rule   *HopPredicate
}

func (e *ACLEntry) ProtoId() proto.ProtoIdType {
	return proto.ACLEntry_TypeID
}

func (e *ACLEntry) String() string {
	return fmt.Sprintf("{Action: %s, Rule: %s}", e.Action, e.Rule)
}

func (e *ACLEntry) Copy() *ACLEntry {
	return &ACLEntry{
		Action: e.Action,
		Rule:   e.Rule.Copy(),
	}
}

var _ proto.Cerealizable = (*HopPredicate)(nil)

type HopPredicate struct {
	IA    addr.IA
	IfIDs []common.IFIDType
}

func (p *HopPredicate) ProtoId() proto.ProtoIdType {
	return proto.HopPredicate_TypeID
}

func (p *HopPredicate) String() string {
	return fmt.Sprintf("{IA: %s, IfIds: %s}", p.IA, p.IfIDs)
}
func (p *HopPredicate) Copy() *HopPredicate {
	if p == nil {
		return nil
	}
	return &HopPredicate{
		IA:    p.IA,
		IfIDs: append([]common.IFIDType{}, p.IfIDs...),
	}
}

func copyOptions(options []Option) []Option {
	copy := make([]Option, 0, len(options))
	for _, option := range options {
		copy = append(copy, Option{
			Weight: option.Weight,
			Policy: option.Policy.Copy(),
		})
	}
	return copy
}

func copyEntries(entries []*ACLEntry) []*ACLEntry {
	copy := make([]*ACLEntry, 0, len(entries))
	for _, entry := range entries {
		copy = append(copy, entry)
	}
	return copy
}

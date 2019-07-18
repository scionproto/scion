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

// File matchers contains matchers for gomock.

package matchers

import (
	"context"
	"fmt"

	"github.com/golang/mock/gomock"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/ctrl/ack"
	"github.com/scionproto/scion/go/lib/ctrl/path_mgmt"
	"github.com/scionproto/scion/go/lib/snet"
)

var _ gomock.Matcher = (*addrIAMatcher)(nil)

type addrIAMatcher struct {
	ia addr.IA
}

// IsSnetAddrWithIA returns a matcher for a snet.Addr with the given IA.
func IsSnetAddrWithIA(ia addr.IA) gomock.Matcher {
	return &addrIAMatcher{ia: ia}
}

func (m *addrIAMatcher) Matches(x interface{}) bool {
	sAddr, ok := x.(*snet.Addr)
	if !ok {
		return false
	}
	return sAddr.IA.Equal(m.ia)
}

func (m *addrIAMatcher) String() string {
	return fmt.Sprintf("Matching addr with IA %v", m.ia)
}

var _ gomock.Matcher = (*AckMsg)(nil)

// AckMsg matches ack messages.
type AckMsg struct {
	Ack ack.Ack
}

// Matches returns whether the matcher matches x.
func (m *AckMsg) Matches(x interface{}) bool {
	ack, ok := x.(*ack.Ack)
	if !ok {
		return false
	}
	return ack.Err == m.Ack.Err && ack.ErrDesc == m.Ack.ErrDesc
}

func (m *AckMsg) String() string {
	return fmt.Sprintf("is ack msg: %v", m.Ack)
}

var _ gomock.Matcher = (*SignedRevs)(nil)

// SignedRevs matches signed revocations against revinfos and checks if they
// are verifiable.
type SignedRevs struct {
	Verifier  path_mgmt.Verifier
	MatchRevs []path_mgmt.RevInfo
}

// Matches returns whether the matcher matches x.
func (m *SignedRevs) Matches(x interface{}) bool {
	sRevs, ok := x.([]*path_mgmt.SignedRevInfo)
	if !ok {
		return false
	}
	revInfos := make(map[path_mgmt.RevInfo]*path_mgmt.RevInfo)
	for _, rev := range sRevs {
		revInfo, err := rev.VerifiedRevInfo(context.Background(), m.Verifier)
		if err != nil {
			return false
		}
		key := *revInfo
		key.RawTimestamp, key.RawTTL = 0, 0
		revInfos[key] = revInfo
	}
	for _, expectedRev := range m.MatchRevs {
		expectedRev.RawTimestamp, expectedRev.RawTTL = 0, 0
		rev, ok := revInfos[expectedRev]
		if !ok {
			return false
		}
		if rev.Active() != nil {
			return false
		}
		delete(revInfos, expectedRev)
	}
	return len(revInfos) == 0
}

func (m *SignedRevs) String() string {
	return fmt.Sprintf("is slice of signed revocations matching %v and verifiable", m.MatchRevs)
}

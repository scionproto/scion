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

package trust

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"
)

// ChainQuery identifies a set of chains that need to be looked up.
type ChainQuery struct {
	// IA is the ISD-AS identifier that must be part of the AS certificate's
	// subject.
	IA addr.IA
	// SubjectKeyID identifies the subject key that the AS certificate must
	// authenticate.
	SubjectKeyID []byte
	// Validity is the validity period of the chain. A certificate c fulfills
	// the validity requirement if c.not_before <= Validity.not_before and
	// c.not_after >= Validity.not_after.
	Validity cppki.Validity
}

// MarshalJSON marshals the chain query for well formated log output.
func (q ChainQuery) MarshalJSON() ([]byte, error) {
	j := struct {
		IA           addr.IA        `json:"isd_as"`
		SubjectKeyID string         `json:"subject_key_id"`
		Validity     cppki.Validity `json:"validity"`
	}{
		IA:           q.IA,
		SubjectKeyID: fmt.Sprintf("%x", q.SubjectKeyID),
		Validity:     q.Validity,
	}
	return json.Marshal(j)

}

// DB is the database interface for trust material.
type DB interface {
	// Chains looks up all chains that match the query.
	Chains(context.Context, ChainQuery) ([][]*x509.Certificate, error)
	// InsertChain inserts the given chain.
	InsertChain(context.Context, []*x509.Certificate) (bool, error)

	// SignedTRC looks up the TRC identified by the id.
	SignedTRC(ctx context.Context, id cppki.TRCID) (cppki.SignedTRC, error)
	// InsertTRC inserts the given TRC. Returns true if the TRC was not yet in
	// the DB.
	InsertTRC(ctx context.Context, trc cppki.SignedTRC) (bool, error)
}

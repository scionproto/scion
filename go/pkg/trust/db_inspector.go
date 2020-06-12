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

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cppki"
	"github.com/scionproto/scion/go/lib/serrors"
)

// DBInspector gives insight about primary ASes of a given ISD based on the TRC
// that is stored in the DB.
type DBInspector struct {
	DB DB
}

// ByAttributes returns a list of primary ASes in the specified ISD that
// hold all the requested attributes. If no attribute is specified, all
// primary ASes are returned.
func (i DBInspector) ByAttributes(ctx context.Context, isd addr.ISD,
	attrs Attribute) ([]addr.IA, error) {

	trcAttrs, err := i.trcAttrs(ctx, isd)
	if err != nil {
		return nil, err
	}
	var matches []addr.IA
	for ia, trcAttributes := range trcAttrs {
		if attrs == Any || attrs.IsSubset(trcAttributes) {
			matches = append(matches, ia)
		}
	}
	return matches, nil
}

// HasAttributes indicates whether an AS holds all the specified attributes.
// The first return value is always false for non-primary ASes.
func (i DBInspector) HasAttributes(ctx context.Context, ia addr.IA, attrs Attribute) (bool, error) {
	trcAttrs, err := i.trcAttrs(ctx, ia.I)
	if err != nil {
		return false, err
	}
	trcAttribute, exists := trcAttrs[ia]
	return exists && attrs.IsSubset(trcAttribute), nil
}

func (i DBInspector) trcAttrs(ctx context.Context, isd addr.ISD) (map[addr.IA]Attribute, error) {
	sTRC, err := i.DB.SignedTRC(ctx, cppki.TRCID{
		ISD:    isd,
		Base:   scrypto.LatestVer,
		Serial: scrypto.LatestVer,
	})
	if err != nil {
		return nil, serrors.WrapStr("failed to load TRC from DB", err)
	}
	if sTRC.IsZero() {
		return nil, serrors.New("TRC not found")
	}
	trc := sTRC.TRC
	attrs := map[addr.IA]Attribute{}
	for _, as := range trc.CoreASes {
		attrs[addr.IA{I: trc.ID.ISD, A: as}] |= Core
	}
	for _, as := range trc.AuthoritativeASes {
		attrs[addr.IA{I: trc.ID.ISD, A: as}] |= Authoritative
	}
	roots, err := rootIAs(trc)
	if err != nil {
		return nil, err
	}
	for _, ia := range roots {
		attrs[ia] |= RootCA
	}
	return attrs, nil
}

func rootIAs(trc cppki.TRC) ([]addr.IA, error) {
	roots, err := trc.RootCerts()
	if err != nil {
		return nil, serrors.WrapStr("failed to extract root certs", err)
	}
	rootIAs := make([]addr.IA, 0, len(roots))
	for _, c := range roots {
		ia, err := cppki.ExtractIA(c.Subject)
		if err != nil {
			return nil, serrors.WrapStr("failed to extract IA from root cert", err)
		}
		if ia == nil {
			continue
		}
		rootIAs = append(rootIAs, *ia)
	}
	return rootIAs, nil
}

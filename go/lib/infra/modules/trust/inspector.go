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

package trust

import (
	"context"

	"github.com/opentracing/opentracing-go"
	opentracingext "github.com/opentracing/opentracing-go/ext"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/internal/metrics"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
)

// Inspector gives insights into the primary ASes of a given ISD.
type Inspector interface {
	// ByAttributes returns a list of primary ASes in the specified ISD that hold
	// all the requested attributes.
	ByAttributes(ctx context.Context, isd addr.ISD, opts infra.ASInspectorOpts) ([]addr.IA, error)
	// HasAttributes indicates whether an AS holds all the specified attributes.
	// The first return value is always false for non-primary ASes.
	HasAttributes(ctx context.Context, ia addr.IA, opts infra.ASInspectorOpts) (bool, error)
}

// DefaultInspector is used to inspect primary ASes.
type DefaultInspector struct {
	Provider CryptoProvider
}

// ByAttributes returns a list of primary ASes in the specified ISD that hold
// all the requested attributes.
func (i DefaultInspector) ByAttributes(ctx context.Context, isd addr.ISD,
	opts infra.ASInspectorOpts) ([]addr.IA, error) {

	l := metrics.InspectorLabels{Type: metrics.ByAttributes}
	ctx = metrics.CtxWith(ctx, metrics.ASInspector)
	span, ctx := opentracing.StartSpanFromContext(ctx, "by_attributes")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("isd", isd)
	span.SetTag("opts", opts)

	trcOpts := infra.TRCOpts{TrustStoreOpts: opts.TrustStoreOpts}
	t, err := i.Provider.GetTRC(ctx, TRCID{ISD: isd, Version: scrypto.LatestVer}, trcOpts)
	defer metrics.Inspector.Request(l.WithResult(errToLabel(err))).Inc()
	if err != nil {
		return nil, err
	}
	ases := make([]addr.IA, 0, len(t.PrimaryASes))
	for as, entry := range t.PrimaryASes {
		if hasAttributes(entry, opts.RequiredAttributes) {
			ases = append(ases, addr.IA{I: isd, A: as})
		}
	}
	return ases, nil
}

// HasAttributes indicates whether an AS holds all the specified attributes.
// The first return value is always false for non-primary ASes.
func (i DefaultInspector) HasAttributes(ctx context.Context, ia addr.IA,
	opts infra.ASInspectorOpts) (bool, error) {

	l := metrics.InspectorLabels{Type: metrics.HasAttributes}
	ctx = metrics.CtxWith(ctx, metrics.ASInspector)
	span, ctx := opentracing.StartSpanFromContext(ctx, "has_attributes")
	defer span.Finish()
	opentracingext.Component.Set(span, "trust")
	span.SetTag("ia", ia)
	span.SetTag("opts", opts)

	trcOpts := infra.TRCOpts{TrustStoreOpts: opts.TrustStoreOpts}
	trc, err := i.Provider.GetTRC(ctx, TRCID{ISD: ia.I, Version: scrypto.LatestVer}, trcOpts)
	defer metrics.Inspector.Request(l.WithResult(errToLabel(err))).Inc()
	if err != nil {
		return false, err
	}
	entry, ok := trc.PrimaryASes[ia.A]
	if !ok {
		return false, nil
	}
	return hasAttributes(entry, opts.RequiredAttributes), nil
}

func hasAttributes(entry trc.PrimaryAS, attrs []infra.Attribute) bool {
	for _, attr := range attrs {
		if !entry.Is(infraToAttr(attr)) {
			return false
		}
	}
	return true
}

// FIXME(roosd): remove when switching to new CP-PKI.
func infraToAttr(attr infra.Attribute) trc.Attribute {
	switch attr {
	case infra.Authoritative:
		return trc.Authoritative
	case infra.Issuing:
		return trc.Issuing
	case infra.Voting:
		return trc.Voting
	default:
		return trc.Core
	}
}

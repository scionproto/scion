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
	"fmt"
	"math/rand"
	"time"

	"github.com/patrickmn/go-cache"

	"github.com/scionproto/scion/go/lib/addr"
	libmetrics "github.com/scionproto/scion/go/lib/metrics"
	"github.com/scionproto/scion/go/lib/prom"
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
		rootIAs = append(rootIAs, ia)
	}
	return rootIAs, nil
}

// CachingInspector caches the results for a certain amount of time.
type CachingInspector struct {
	Inspector Inspector

	// Cache keeps track of recently used certificates. If nil no cache is used.
	// This API is experimental.
	Cache              *cache.Cache
	CacheHits          libmetrics.Counter
	MaxCacheExpiration time.Duration
}

// ByAttributes returns a list of primary ASes in the specified ISD that
// hold all the requested attributes. If no attribute is specified, all
// primary ASes are returned.
func (i CachingInspector) ByAttributes(ctx context.Context, isd addr.ISD,
	attrs Attribute) ([]addr.IA, error) {

	key := fmt.Sprintf("by-attrs-%d-%d", isd, attrs)
	cachedAttrs, ok := i.cacheGet(key, "by_attributes")
	if ok {
		return cachedAttrs.([]addr.IA), nil
	}

	matches, err := i.Inspector.ByAttributes(ctx, isd, attrs)
	if err != nil {
		return nil, err
	}
	i.cacheAdd(key, matches, i.cacheExpiration())
	return matches, nil
}

// HasAttributes indicates whether an AS holds all the specified attributes.
// The first return value is always false for non-primary ASes.
func (i CachingInspector) HasAttributes(ctx context.Context, ia addr.IA,
	attrs Attribute) (bool, error) {

	key := fmt.Sprintf("has-attrs-%s-%d", ia, attrs)
	cached, ok := i.cacheGet(key, "has_attributes")
	if ok {
		return cached.(bool), nil
	}

	hasAttributes, err := i.Inspector.HasAttributes(ctx, ia, attrs)
	if err != nil {
		return false, err
	}
	i.cacheAdd(key, hasAttributes, i.cacheExpiration())
	return hasAttributes, nil
}

func (i CachingInspector) cacheGet(key string, reqType string) (interface{}, bool) {
	if i.Cache == nil {
		return nil, false
	}
	result, ok := i.Cache.Get(key)

	resultValue := "hit"
	if !ok {
		resultValue = "miss"
	}
	libmetrics.CounterInc(libmetrics.CounterWith(i.CacheHits,
		"type", reqType,
		prom.LabelResult, resultValue,
	))

	return result, ok
}

func (i CachingInspector) cacheAdd(key string, value interface{}, d time.Duration) {
	if i.Cache == nil {
		return
	}
	i.Cache.Add(key, value, d)
}

func (i CachingInspector) cacheExpiration() time.Duration {
	dur := i.MaxCacheExpiration
	if dur == 0 {
		dur = defaultCacheExpiration
	}
	return time.Duration(rand.Int63n(int64(dur-(dur/2))) + int64(dur/2))
}

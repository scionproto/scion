// Copyright 2022 ETH Zurich
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

package drkey

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/drkey"
	"github.com/scionproto/scion/pkg/log"
)

type Level1Engine interface {
	GetLevel1Key(ctx context.Context, meta drkey.Level1Meta) (drkey.Level1Key, error)
	GetLevel1PrefetchInfo() []Level1PrefetchInfo
}

// Prefetcher is in charge of getting the level 1 keys before they expire.
type Prefetcher struct {
	LocalIA addr.IA
	Engine  Level1Engine
	// XXX(JordiSubira): At the moment we assume "global" KeyDuration, i.e.
	// every AS involved uses the same EpochDuration. This will be improve
	// further in the future, so that the prefetcher get keys in advance
	// based on the epoch established by the AS which derived the first
	// level key.
	KeyDuration time.Duration
}

// Name returns the tasks name.
func (f *Prefetcher) Name() string {
	return fmt.Sprintf("drkey_prefetcher_%s", f.LocalIA)
}

// Run requests the level 1 keys to other CSs.
func (f *Prefetcher) Run(ctx context.Context) {
	logger := log.FromCtx(ctx)
	var wg sync.WaitGroup
	keysMeta := f.Engine.GetLevel1PrefetchInfo()
	logger.Debug("Prefetching level 1 DRKeys", "AS, proto:", keysMeta)
	when := time.Now().Add(f.KeyDuration)
	for _, key := range keysMeta {
		key := key
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			getLevel1Key(ctx, f.Engine, key.IA, f.LocalIA, key.Proto, when)
		}()
	}
	wg.Wait()
}

func getLevel1Key(
	ctx context.Context,
	engine Level1Engine,
	srcIA, dstIA addr.IA,
	proto drkey.Protocol,
	valTime time.Time,
) {

	meta := drkey.Level1Meta{
		Validity: valTime,
		SrcIA:    srcIA,
		DstIA:    dstIA,
		ProtoId:  proto,
	}
	ctx = context.WithValue(ctx, fromPrefetcher{}, true)
	if _, err := engine.GetLevel1Key(ctx, meta); err != nil {
		log.FromCtx(ctx).Error(
			"Failed to prefetch the level 1 key",
			"remote_isd_as", srcIA,
			"protocol", proto,
			"error", err,
		)
	}
}

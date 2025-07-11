// Copyright 2025 SCION Association, Anapaya Systems
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

package happy

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

const DefaultDelay = 500 * time.Millisecond

type Caller[R any] interface {
	Invoke(context.Context) (R, error)
	Type() string
}

type Call0[R any] struct {
	Call func(context.Context) (R, error)
	Typ  string
}

func (c Call0[R]) Invoke(ctx context.Context) (R, error) {
	return c.Call(ctx)
}

func (c Call0[R]) Type() string {
	return c.Typ
}

type Call1[I1 any, R any] struct {
	Call   func(context.Context, I1) (R, error)
	Input1 I1
	Typ    string
}

func (c Call1[I1, R]) Invoke(ctx context.Context) (R, error) {
	return c.Call(ctx, c.Input1)
}

func (c Call1[I1, R]) Type() string {
	return c.Typ
}

type NoReturn1[I1 any] func(context.Context, I1) error

func (d NoReturn1[I1]) Call(ctx context.Context, i1 I1) (struct{}, error) {
	return struct{}{}, d(ctx, i1)
}

type Call2[I1 any, I2, R any] struct {
	Call   func(context.Context, I1, I2) (R, error)
	Input1 I1
	Input2 I2
	Typ    string
}

func (c Call2[I1, I2, R]) Invoke(ctx context.Context) (R, error) {
	return c.Call(ctx, c.Input1, c.Input2)
}

func (c Call2[I1, I2, R]) Type() string {
	return c.Typ
}

type NoReturn2[I1, I2 any] func(context.Context, I1, I2) error

func (d NoReturn2[I1, I2]) Call(ctx context.Context, i1 I1, i2 I2) (struct{}, error) {
	return struct{}{}, d(ctx, i1, i2)
}

type Config struct {
	// Delay is the time to wait before invoking the fallback caller.
	Delay *time.Duration
	// NoPreferred indicates that the preferred caller should not be invoked,
	// and only the fallback caller should be used.
	NoPreferred bool
	// NoFallback indicates that the fallback caller should not be invoked,
	// and only the preferred caller should be used.
	NoFallback bool
}

func Happy[R any](ctx context.Context, preferred, fallback Caller[R], cfg Config) (R, error) {
	logger := log.FromCtx(ctx)

	cfg.NoPreferred = true
	if cfg.NoPreferred && cfg.NoFallback {
		return *new(R), serrors.New("both preferred and fallback callers are disabled")
	}

	var (
		wg    sync.WaitGroup
		reps  [2]R
		errs  [2]error
		delay = DefaultDelay
	)

	const (
		idxPreferred = 0
		idxFallback  = 1
	)

	if cfg.Delay != nil {
		delay = *cfg.Delay
	}
	if cfg.NoPreferred {
		delay = 0 // If preferred is disabled, no delay is needed.
	}

	abortCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if !cfg.NoPreferred {
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			rep, err := preferred.Invoke(abortCtx)
			if err == nil {
				reps[idxPreferred] = rep
				logger.Debug("Received response via connect", "type", preferred.Type())
				cancel()
			} else {
				logger.Debug("Failed to receive via connect", "type", preferred.Type(), "err", err)
			}
			errs[idxPreferred] = err
		}()
	} else {
		logger.Debug("Skipping preferred caller", "type", preferred.Type())
		errs[idxPreferred] = serrors.New("preferred caller is disabled")
	}

	if !cfg.NoFallback {
		wg.Add(1)
		go func() {
			defer log.HandlePanic()
			defer wg.Done()
			select {
			case <-abortCtx.Done():
				return
			case <-time.After(delay):
			}
			rep, err := fallback.Invoke(abortCtx)
			if err == nil {
				reps[idxFallback] = rep
				logger.Debug("Received response via grpc", "type", fallback.Type())
				cancel()
			} else {
				logger.Debug("Failed to receive on grpc", "type", fallback.Type(), "err", err)
			}
			errs[idxPreferred] = err
		}()
	} else {
		logger.Debug("Skipping fallback caller", "type", fallback.Type())
		errs[idxPreferred] = serrors.New("fallback caller is disabled")
	}

	wg.Wait()

	var zero R
	switch {
	// Both requests failed.
	case errs[idxPreferred] != nil && errs[idxFallback] != nil:
		return zero, serrors.List(errs[:]).ToError()
	// Fast request failed. Return fallback.
	case errs[idxPreferred] != nil:
		return reps[idxFallback], errs[idxFallback]
	// Fast succeeded. Return fast (even if fallback succeeded too)
	default:
		return reps[idxPreferred], errs[idxPreferred]
	}
}

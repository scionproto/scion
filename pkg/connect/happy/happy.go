package happy

import (
	"context"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
)

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

func Happy[R any](ctx context.Context, fast, slow Caller[R]) (R, error) {
	logger := log.FromCtx(ctx)

	var (
		wg   sync.WaitGroup
		reps [2]R
		errs [2]error
	)

	wg.Add(2)
	abortCtx, cancel := context.WithCancel(ctx)
	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		rep, err := fast.Invoke(abortCtx)
		if err == nil {
			reps[0] = rep
			logger.Debug("Received response via connect", "type", fast.Type())
			cancel()
		} else {
			logger.Debug("Failed to receive via connect", "type", fast.Type(), "err", err)
		}
		errs[0] = err
	}()

	go func() {
		defer log.HandlePanic()
		defer wg.Done()
		select {
		case <-abortCtx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		rep, err := slow.Invoke(abortCtx)
		if err == nil {
			reps[0] = rep
			logger.Debug("Received response via grpc", "type", slow.Type())
			cancel()
		} else {
			logger.Debug("Failed to receive on grpc", "type", slow.Type(), "err", err)
		}
		errs[1] = err
	}()

	wg.Wait()

	var zero R
	switch {
	// Both requests failed.
	case errs[0] != nil && errs[1] != nil:
		return zero, serrors.List(errs[:]).ToError()
	// Fast request failed. Return slow.
	case errs[0] != nil:
		return reps[1], nil
	// Fast succeeded. Return fast (even if slow succeeded too)
	default:
		return reps[0], nil
	}
}

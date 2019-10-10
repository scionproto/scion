// Copyright 2018 Anapaya Systems
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

package periodic

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/periodic/metrics"
	"github.com/scionproto/scion/go/lib/periodic/metrics/mock_metrics"
)

type taskFunc func(context.Context)

func (tf taskFunc) Run(ctx context.Context) {
	tf(ctx)
}

func (tf taskFunc) Name() string {
	return "Test function"
}

func TestPeriodicExecution(t *testing.T) {
	met := initMetrics(t)
	metrics.NewMetric = func(prefix string) metrics.ExportMetric {
		return met
	}

	cnt := 0
	fn := taskFunc(func(ctx context.Context) {
		cnt++
	})
	p := 10 * time.Millisecond
	r := Start(fn, p, time.Microsecond)
	time.Sleep(11 * p)
	r.Stop()
	assert.GreaterOrEqual(t, cnt, 10, "Must run at least 10 times within 10+1 period time")
}

func TestKillExitsLongRunningFunc(t *testing.T) {
	errChan := make(chan error, 1)
	fn := taskFunc(func(ctx context.Context) {
		// Simulate long work by blocking on the done channel.
		select {
		case <-ctx.Done():
		case <-time.After(100 * time.Millisecond):
			t.Fatalf("goroutine took too long to finish")
		}
		errChan <- ctx.Err()
	})
	p := 1 * time.Millisecond
	r := Start(fn, p, 300*time.Millisecond)
	time.Sleep(2 * p)
	r.Kill()
	select {
	case err := <-errChan:
		assert.Equal(t, context.Canceled, err, "Context should have been canceled")
	case <-time.After(200 * time.Millisecond):
		t.Fatalf("time out while waiting on err")
	}
}

func TestTaskDoesntRunAfterKill(t *testing.T) {
	cnt := make(chan struct{}, 50)
	fn := taskFunc(func(ctx context.Context) {
		cnt <- struct{}{}
	})
	p := 20 * time.Millisecond
	r := Start(fn, p, 2*p)
	go func() {
		<-cnt // discard the first normal periodic run
		r.Kill()
		return
	}()
	time.Sleep(5 * p)
	assert.Equal(t, len(cnt), 0)
}

func TestTriggerNow(t *testing.T) {
	got, want := 0, 10

	cnt := make(chan struct{}, 50)
	fn := taskFunc(func(ctx context.Context) {
		cnt <- struct{}{}
	})

	p := 10 * time.Millisecond
	r := Start(fn, p, 3*p)
	go func() {
		<-cnt // discard the first normal periodic run
		for i := 0; i < want; i++ {
			r.TriggerRun()
		}
		return
	}()

	time.Sleep(2 * p) // wait two periods
	got = len(cnt)    // channel want values because of trigger, and maybe plus one
	assert.GreaterOrEqual(t, got, want, "Must run %v times within 2 period time", want)
}

func TestMain(m *testing.M) {
	log.Root().SetHandler(log.DiscardHandler())
	os.Exit(m.Run())
}

func initMetrics(t *testing.T) *mock_metrics.MockExportMetric {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	met := mock_metrics.NewMockExportMetric(ctrl)
	met.EXPECT().Period(gomock.Any()).Return().AnyTimes()
	met.EXPECT().StartTimestamp(gomock.Any()).Return().AnyTimes()
	met.EXPECT().Runtime(gomock.Any()).Return().AnyTimes()
	met.EXPECT().Event(gomock.Any()).Return().AnyTimes()
	return met
}

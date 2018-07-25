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

// Package integration provides function to simplify the creation of integration tests.
package integration

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/util"
)

// Integration can be used to run integration tests.
type Integration interface {
	// Name returns the name of the test
	Name() string
	// StartServer should start the server listening on the address dst.
	// StartServer should return immediately.
	// The context should be used to make the server cancellable.
	StartServer(ctx context.Context, dst addr.IA) (Waiter, error)
	// StartClient should start the client on the src address connecting to the dst address.
	// StartClient should return immediately.
	// The context should be used to make the client cancellable.
	StartClient(ctx context.Context, src, dst addr.IA) (Waiter, error)
}

// Waiter is a descriptor of a process running in the integration test.
// It should be used to wait on completion of the process.
type Waiter interface {
	// Wait should block until the underlying program is terminated.
	Wait() error
}

// Init initializes the integration test, it adds and validates the command line flags.
func Init() error {
	addTestFlags()
	return validateFlags()
}

func addTestFlags() {
	log.AddLogConsFlags()
}

func validateFlags() error {
	flag.Parse()
	if err := log.SetupFromFlags(""); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		flag.Usage()
		return err
	}
	return nil
}

// LoadASList loads the AS list from the as_list yaml file.
func LoadASList() (*util.ASList, error) {
	return util.LoadASList("gen/as_list.yml")
}

// AllIAs returns all IA from asList.
func AllIAs(asList *util.ASList) []addr.IA {
	return append([]addr.IA(nil), append(asList.Core, asList.NonCore...)...)
}

// IAPair is a source, destination pair. The client (Src) will dial the server (Dst).
type IAPair struct {
	Src addr.IA
	Dst addr.IA
}

// GenerateAllSrcDst generates the cartesian product shuffle(srcASes) x shuffle(dstASes).
func GenerateAllSrcDst(srcASes, dstASes []addr.IA) []IAPair {
	shuffle(len(srcASes), func(i, j int) {
		srcASes[i], srcASes[j] = srcASes[j], srcASes[i]
	})
	shuffle(len(dstASes), func(i, j int) {
		dstASes[i], dstASes[j] = dstASes[j], dstASes[i]
	})
	pairs := make([]IAPair, 0, len(srcASes)*len(dstASes))
	for _, src := range srcASes {
		for _, dst := range dstASes {
			pairs = append(pairs, IAPair{src, dst})
		}
	}
	return pairs
}

// interface kept similar to go 1.10
func shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		swap(i, j)
	}
}

type serverStop struct {
	cancel context.CancelFunc
	wait   Waiter
}

func (s *serverStop) Close() error {
	s.cancel()
	s.wait.Wait()
	return nil
}

// StartServer runs a server. The server can be stopped by calling Close() on the returned Closer.
func StartServer(in Integration, dst addr.IA) (io.Closer, error) {
	serverCtx, serverCancel := context.WithCancel(context.Background()) // add method to run a single server that returns a closer (go chanel to close).
	s, err := in.StartServer(serverCtx, dst)
	if err != nil {
		serverCancel()
		return nil, err
	}
	return &serverStop{serverCancel, s}, nil
}

// RunClient runs a client on the given IAPair.
// If the client does not finish until timeout it is killed.
func RunClient(in Integration, pair IAPair, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := in.StartClient(ctx, pair.Src, pair.Dst)
	if err != nil {
		return err
	}
	if err = c.Wait(); err != nil {
		return err
	}
	return nil
}

// ExecuteTimed executes f and prints how long f took to StdOut. Returns the error of f.
func ExecuteTimed(name string, f func() error) error {
	start := time.Now()
	err := f()
	elapsed := time.Since(start)
	fmt.Printf("Test %v successful, used %v\n", name, elapsed)
	return err
}

// ExtractUniqueDsts returns all unique destinations in pairs.
func ExtractUniqueDsts(pairs []IAPair) []addr.IA {
	uniqueDsts := make(map[addr.IA]bool)
	var res []addr.IA
	for _, pair := range pairs {
		if !uniqueDsts[pair.Dst] {
			res = append(res, pair.Dst)
			uniqueDsts[pair.Dst] = true
		}
	}
	return res
}

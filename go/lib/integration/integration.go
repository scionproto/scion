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

// IAPair is a source, destination pair. The client (Src) will dial the server (Dst).
type IAPair struct {
	Src addr.IA
	Dst addr.IA
}

// GenerateAllSrcDst generates the cartesian product shuffle(asList) x shuffle(asList).
func GenerateAllSrcDst(asList *util.ASList) []IAPair {
	allSrcASes := append(asList.Core, asList.NonCore...)
	allDstASes := append([]addr.IA(nil), allSrcASes...)
	shuffle(len(allSrcASes), func(i, j int) {
		allSrcASes[i], allSrcASes[j] = allSrcASes[j], allSrcASes[i]
		allDstASes[i], allDstASes[j] = allDstASes[j], allDstASes[i]
	})
	pairs := make([]IAPair, 0, len(allSrcASes)*len(allDstASes))
	for _, src := range allSrcASes {
		for _, dst := range allDstASes {
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

// RunTests runs the client and server for each IAPair.
// In case of an error the function is terminated immediately.
func RunTests(in Integration, pairs []IAPair) error {
	start := time.Now()

	// First run all servers
	dsts := extractUniqueDsts(pairs)
	for _, dst := range dsts {
		serverCtx, serverCancel := context.WithCancel(context.Background())
		s, err := in.StartServer(serverCtx, dst)
		if err != nil {
			serverCancel()
			return err
		}
		defer func() {
			// make sure the server is properly killed.
			serverCancel()
			s.Wait()
		}()
	}

	// Now start the clients for srcDest pair
	for i, conn := range pairs {
		log.Info(fmt.Sprintf("Test %v: %v -> %v (%v/%v)",
			in.Name(), conn.Src, conn.Dst, i, len(pairs)))

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		c, err := in.StartClient(ctx, conn.Src, conn.Dst)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error during start of the client: %s\n", err)
			return err
		}
		if err = c.Wait(); err != nil {
			fmt.Fprintf(os.Stderr, "Error during client execution: %s\n", err)
			return err
		}
	}

	elapsed := time.Since(start)
	fmt.Printf("Test %v successful, used %v\n", in.Name(), elapsed)

	return nil
}

func extractUniqueDsts(pairs []IAPair) []addr.IA {
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

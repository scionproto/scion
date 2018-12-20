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

// Package integration simplifies the creation of integration tests.
package integration

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kormat/fmt15"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/log"
	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/lib/topology"
	"github.com/scionproto/scion/go/lib/util"
)

const (
	// StartServerTimeout is the timeout for starting a server.
	StartServerTimeout = 4 * time.Second
	// DefaultRunTimeout is the timeout when running a server or a client.
	DefaultRunTimeout = 8 * time.Second
	// CtxTimeout is the timeout a context waits before being killed
	CtxTimeout = 5 * time.Second
	// RetryTimeout is the timeout between different attempts
	RetryTimeout = time.Second / 2
)

type iaArgs []addr.IA

func (a iaArgs) String() string {
	rawIAs := make([]string, len(a))
	for i, ia := range a {
		rawIAs[i] = ia.String()
	}
	return strings.Join(rawIAs, ",")
}

// Set implements flag.Value.Set().
func (a *iaArgs) Set(value string) error {
	rawIAs := strings.Split(value, ",")
	for _, rawIA := range rawIAs {
		ia, err := addr.IAFromString(rawIA)
		if err != nil {
			return err
		}
		*a = append(*a, ia)
	}
	return nil
}

var (
	srcIAs iaArgs
	dstIAs iaArgs
)

// Integration can be used to run integration tests.
type Integration interface {
	// Name returns the name of the test
	Name() string
	// StartServer should start the server listening on the address dst.
	// StartServer should return after it is ready to accept clients.
	// The context should be used to make the server cancellable.
	StartServer(ctx context.Context, dst snet.Addr) (Waiter, error)
	// StartClient should start the client on the src address connecting to the dst address.
	// StartClient should return immediately.
	// The context should be used to make the client cancellable.
	StartClient(ctx context.Context, src, dst snet.Addr) (Waiter, error)
}

// Waiter is a descriptor of a process running in the integration test.
// It should be used to wait on completion of the process.
type Waiter interface {
	// Wait should block until the underlying program is terminated.
	Wait() error
}

// Init initializes the integration test, it adds and validates the command line flags,
// and initializes logging.
func Init(name string) error {
	addTestFlags()
	return validateFlags(name)
}

func addTestFlags() {
	log.ConsoleLevel = "info"
	log.AddLogConsFlags()
	log.AddLogFileFlags()
	flag.Var(&srcIAs, "src", "Source ISD-ASes (comma separated list)")
	flag.Var(&dstIAs, "dst", "Destination ISD-ASes (comma separated list)")
}

func validateFlags(name string) error {
	flag.Parse()
	if err := log.SetupFromFlags(name); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		flag.Usage()
		return err
	}
	asList, err := util.LoadASList("gen/as_list.yml")
	if err != nil {
		return err
	}
	if len(srcIAs) == 0 {
		srcIAs = asList.AllASes()
	}
	if len(dstIAs) == 0 {
		dstIAs = asList.AllASes()
	}
	return nil
}

// IAPair is a source, destination pair. The client (Src) will dial the server (Dst).
type IAPair struct {
	Src snet.Addr
	Dst snet.Addr
}

// IAPairs returns all IAPairs that should be tested.
func IAPairs(hostAddr HostAddr) []IAPair {
	return generateAllSrcDst(hostAddr, false)
}

// UniqueIAPairs returns all distinct IAPairs that should be tested.
func UniqueIAPairs(hostAddr HostAddr) []IAPair {
	return generateAllSrcDst(hostAddr, true)
}

func generateSrcDst(hostAddr HostAddr) ([]snet.Addr, []snet.Addr) {
	srcASes := make([]snet.Addr, 0, len(srcIAs))
	for _, src := range srcIAs {
		srcASes = append(srcASes, hostAddr(src))
	}
	dstASes := make([]snet.Addr, 0, len(dstIAs))
	for _, dst := range dstIAs {
		dstASes = append(dstASes, hostAddr(dst))
	}
	shuffle(len(srcASes), func(i, j int) {
		srcASes[i], srcASes[j] = srcASes[j], srcASes[i]
	})
	shuffle(len(dstASes), func(i, j int) {
		dstASes[i], dstASes[j] = dstASes[j], dstASes[i]
	})
	return srcASes, dstASes
}

// generateAllSrcDst generates the cartesian product shuffle(srcASes) x shuffle(dstASes).
// It omits pairs where srcAS==dstAS, if unique is true.
func generateAllSrcDst(hostAddr HostAddr, unique bool) []IAPair {
	srcASes, dstASes := generateSrcDst(hostAddr)
	pairs := make([]IAPair, 0, len(srcASes)*len(dstASes))
	for _, src := range srcASes {
		for _, dst := range dstASes {
			if !unique || !src.IA.Eq(dst.IA) {
				pairs = append(pairs, IAPair{src, dst})
			}
		}
	}
	return pairs
}

type HostAddr func(ia addr.IA) snet.Addr

// DispAddr reads the BS host Addr from the topology for the specified IA. In general this
// could be the IP of any service (PS/BS/CS) in that IA because they share the same dispatcher in
// the dockerized topology.
// The host IP is used as client or server address in the tests because the testing container is
// connecting to the dispatcher of the services.
var DispAddr HostAddr = func(ia addr.IA) snet.Addr {
	path := fmt.Sprintf("gen/ISD%d/AS%s/endhost/topology.json", ia.I, ia.A.FileFmt())
	topo, err := topology.LoadFromFile(path)
	if err != nil {
		log.Error("Error loading topology", "err", err)
		os.Exit(1)
	}
	bs := topo.BS["bs"+ia.FileFmt(false)+"-1"]
	return snet.Addr{Host: &addr.AppAddr{L3: bs.IPv4.PublicAddr().L3}, IA: ia}
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

// WithTimestamp returns s with the now timestamp prefixed.
// This is helpful for logging staments to stdout/stderr or in a file where the logger isn't used.
func WithTimestamp(s string) string {
	return fmt.Sprintf("%v %s", time.Now().Format(fmt15.TimeFmt), s)
}

// StartServer runs a server. The server can be stopped by calling Close() on the returned Closer.
// To start a server with a custom context use in.StartServer directly.
func StartServer(in Integration, dst snet.Addr) (io.Closer, error) {
	serverCtx, serverCancel := context.WithCancel(context.Background())
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
	level := log.LvlInfo
	result := "successful"
	if err != nil {
		result = "failed"
		level = log.LvlError
	}
	elapsed := time.Since(start)
	log.Log(level, fmt.Sprintf("Test %s %s, used %v\n", name, result, elapsed))
	return err
}

// ExtractUniqueDsts returns all unique destinations in pairs.
func ExtractUniqueDsts(pairs []IAPair) []snet.Addr {
	uniqueDsts := make(map[snet.Addr]bool)
	var res []snet.Addr
	for _, pair := range pairs {
		if !uniqueDsts[pair.Dst] {
			res = append(res, pair.Dst)
			uniqueDsts[pair.Dst] = true
		}
	}
	return res
}

// RunBinaryTests runs the client and server for each IAPair. A number of tests are run in parallel
// In case of an error the function is terminated immediately.
func RunBinaryTests(in Integration, pairs []IAPair, timeout time.Duration) error {
	if timeout == 0 {
		timeout = DefaultRunTimeout
	}
	return runTests(in, pairs, 1, func(idx int, pair IAPair) error {
		// Start server
		s, err := StartServer(in, pair.Dst)
		if err != nil {
			log.Error(fmt.Sprintf("Error in server: %s", pair.Dst.String()), "err", err)
			return err
		}
		defer s.Close()
		// Start client
		log.Info(fmt.Sprintf("Test %v: %v -> %v (%v/%v)", in.Name(), pair.Src.IA, pair.Dst.IA,
			idx+1, len(pairs)))
		if err := RunClient(in, pair, timeout); err != nil {
			msg := fmt.Sprintf("Error in client: %v -> %v (%v/%v)",
				pair.Src.IA, pair.Dst.IA, idx+1, len(pairs))
			log.Error(msg, "err", err)
			return err
		}
		return nil
	})
}

// RunUnaryTests runs the client for each IAPair.
// In case of an error the function is terminated immediately.
func RunUnaryTests(in Integration, pairs []IAPair, timeout time.Duration) error {
	if timeout == 0 {
		timeout = DefaultRunTimeout
	}
	return runTests(in, pairs, 2, func(idx int, pair IAPair) error {
		log.Info(fmt.Sprintf("Test %v: %v -> %v (%v/%v)",
			in.Name(), pair.Src.IA, pair.Dst.IA, idx+1, len(pairs)))
		// Start client
		if err := RunClient(in, pair, timeout); err != nil {
			msg := fmt.Sprintf("Error in client: %v -> %v (%v/%v)",
				pair.Src.IA, pair.Dst.IA, idx+1, len(pairs))
			log.Error(msg, "err", err)
			return err
		}
		return nil
	})
}

// runTests runs the testF for all the given IAPairs in parallel.
func runTests(in Integration, pairs []IAPair, maxGoRoutines int,
	testF func(int, IAPair) error) error {

	return ExecuteTimed(in.Name(), func() error {
		errors := make(chan error, len(pairs))
		workChan := make(chan workFunc, len(pairs))
		for i := range pairs {
			idx, pair := i, pairs[i]
			workChan <- func() error {
				return testF(idx, pair)
			}
		}
		// Run tests in parallel
		return workInParallel(workChan, errors, maxGoRoutines)
	})
}

type workFunc func() error

func workInParallel(workChan chan workFunc, errors chan error, maxGoRoutines int) error {
	var wg sync.WaitGroup
	for i := 1; i <= maxGoRoutines; i++ {
		wg.Add(1)
		go func() {
			defer log.LogPanicAndExit()
			defer wg.Done()
			for work := range workChan {
				err := work()
				if err != nil {
					errors <- err
				}
			}
		}()
	}
	close(workChan)
	wg.Wait()
	return errFromChan(errors)
}

func errFromChan(errors chan error) error {
	select {
	case err := <-errors:
		return err
	default:
		return nil
	}
}

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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/topology"
)

const (
	// StartServerTimeout is the timeout for starting a server.
	StartServerTimeout = 40 * time.Second
	// DefaultRunTimeout is the timeout when running a server or a client.
	DefaultRunTimeout = 20 * time.Second
	// CtxTimeout is the timeout a context waits before being killed
	CtxTimeout = 2 * time.Second
	// RetryTimeout is the timeout between different attempts
	RetryTimeout = time.Second / 2
	// DaemonAddressesFile is the default file for SCIOND addresses in a topology created
	// with the topology generator.
	DaemonAddressesFile = "sciond_addresses.json"
)

var (
	// LoadedASList exposes the ASList loaded during Init
	LoadedASList *ASList
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
		ia, err := addr.ParseIA(rawIA)
		if err != nil {
			return err
		}
		*a = append(*a, ia)
	}
	return nil
}

// Flags.
var (
	logConsole string
	srcIAs     iaArgs
	dstIAs     iaArgs
	outDir     string
)

// Integration can be used to run integration tests.
type Integration interface {
	// Name returns the name of the test
	Name() string
	// StartServer should start the server listening on the address dst.
	// StartServer should return after it is ready to accept clients.
	// The context should be used to make the server cancellable.
	StartServer(ctx context.Context, dst *snet.UDPAddr) (Waiter, error)
	// StartClient should start the client on the src address connecting to the dst address.
	// StartClient should return immediately.
	// The context should be used to make the client cancellable.
	StartClient(ctx context.Context, src, dst *snet.UDPAddr) (*BinaryWaiter, error)
}

// Waiter is a descriptor of a process running in the integration test.
// It should be used to wait on completion of the process.
type Waiter interface {
	// Wait should block until the underlying program is terminated.
	Wait() error
}

// Init initializes the integration test, it adds and validates the command line flags,
// and initializes logging.
func Init() error {
	addTestFlags()
	if err := validateFlags(); err != nil {
		return err
	}
	initAddrs()
	initDockerArgs()
	return nil
}

// GenFile returns the path for the given file in the gen folder.
func GenFile(file string) string {
	return filepath.Join(outDir, "gen", file)
}

// LogDir returns the path for logs.
func LogDir() string {
	return filepath.Join(outDir, "logs")
}

func addTestFlags() {
	flag.StringVar(&logConsole, "log.console", "info",
		"Console logging level: trace|debug|info|warn|error|crit")
	flag.Var(&srcIAs, "src", "Source ISD-ASes (comma separated list)")
	flag.Var(&dstIAs, "dst", "Destination ISD-ASes (comma separated list)")
	flag.StringVar(&outDir, "outDir", ".",
		"path to the output directory that contains gen and logs folders (default: .).")
}

func validateFlags() error {
	flag.Parse()
	logCfg := log.Config{
		Console: log.ConsoleConfig{
			Level:           logConsole,
			StacktraceLevel: "none",
			DisableCaller:   true,
		}}
	if err := log.Setup(logCfg); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		flag.Usage()
		return err
	}
	var err error
	LoadedASList, err = LoadASList(GenFile("as_list.yml"))
	if err != nil {
		return err
	}
	if len(srcIAs) == 0 {
		srcIAs = LoadedASList.AllASes()
	}
	if len(dstIAs) == 0 {
		dstIAs = LoadedASList.AllASes()
	}
	return nil
}

// IAPair is a source, destination pair. The client (Src) will dial the server (Dst).
type IAPair struct {
	Src, Dst *snet.UDPAddr
}

// IAPairs returns all IAPairs that should be tested.
func IAPairs(hostAddr HostAddr) []IAPair {
	return generateAllSrcDst(hostAddr, false)
}

// UniqueIAPairs returns all distinct IAPairs that should be tested.
func UniqueIAPairs(hostAddr HostAddr) []IAPair {
	return generateAllSrcDst(hostAddr, true)
}

func generateSrcDst(hostAddr HostAddr) ([]*snet.UDPAddr, []*snet.UDPAddr) {
	srcASes := make([]*snet.UDPAddr, 0, len(srcIAs))
	for _, src := range srcIAs {
		srcASes = append(srcASes, hostAddr(src))
	}
	dstASes := make([]*snet.UDPAddr, 0, len(dstIAs))
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
			if !unique || !src.IA.Equal(dst.IA) {
				pairs = append(pairs, IAPair{src, dst})
			}
		}
	}
	return pairs
}

type HostAddr func(ia addr.IA) *snet.UDPAddr

// CSAddr reads the tester host Addr from the topology for the specified IA.
// If the address cannot be found, the CS address is returned.
var CSAddr HostAddr = func(ia addr.IA) *snet.UDPAddr {
	if a := loadAddr(ia); a != nil {
		return a
	}
	if raw, err := os.ReadFile(GenFile("networks.conf")); err == nil {
		pattern := fmt.Sprintf("tester_%s = (.*)", addr.FormatIA(ia, addr.WithFileSeparator()))
		matches := regexp.MustCompile(pattern).FindSubmatch(raw)
		if len(matches) == 2 {
			return &snet.UDPAddr{IA: ia, Host: &net.UDPAddr{IP: net.ParseIP(string(matches[1]))}}
		}
	}
	path := GenFile(
		filepath.Join(
			addr.FormatAS(ia.AS(), addr.WithDefaultPrefix(), addr.WithFileSeparator()),
			"topology.json",
		),
	)
	topo, err := topology.RWTopologyFromJSONFile(path)
	if err != nil {
		log.Error("Error loading topology", "err", err)
		os.Exit(1)
	}
	cs := topo.CS["cs"+addr.FormatIA(ia, addr.WithFileSeparator())+"-1"]
	return &snet.UDPAddr{IA: ia, Host: cs.SCIONAddress}
}

var addrs map[addr.IA]*snet.UDPAddr

func initAddrs() {
	var err error
	addrs, err = LoadNetworkAllocs()
	if err != nil {
		log.Error("Loading network allocations failed", "err", err)
		os.Exit(1)
	}
}

func loadAddr(ia addr.IA) *snet.UDPAddr {
	if addrs == nil {
		return nil
	}
	return addrs[ia]
}

// interface kept similar to go 1.10
func shuffle(n int, swap func(i, j int)) {
	for i := n - 1; i > 0; i-- {
		j := rand.IntN(i + 1)
		swap(i, j)
	}
}

type serverStop struct {
	cancel context.CancelFunc
	wait   Waiter
}

func (s *serverStop) Close() error {
	s.cancel()
	return s.wait.Wait()
}

// WithTimestamp returns s with the now timestamp prefixed.
// This is helpful for logging staments to stdout/stderr or in a file where the logger isn't used.
func WithTimestamp(s string) string {
	return fmt.Sprintf("%v %s", time.Now().UTC().Format(common.TimeFmt), s)
}

// StartServer runs a server. The server can be stopped by calling Close() on the returned Closer.
// To start a server with a custom context use in.StartServer directly.
func StartServer(in Integration, dst *snet.UDPAddr) (io.Closer, error) {
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
func RunClient(in Integration, pair IAPair, timeout time.Duration,
	checkOutput func([]byte) error) error {

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	c, err := in.StartClient(ctx, pair.Src, pair.Dst)
	if err != nil {
		return serrors.Wrap("starting client", err)
	}
	if err = c.Wait(); err != nil {
		return serrors.Wrap("waiting for completion", err)
	}
	if checkOutput == nil {
		return nil
	}
	if err := checkOutput(c.Output()); err != nil {
		return serrors.Wrap("checking output", err)
	}
	return nil
}

// ExecuteTimed executes f and prints how long f took to StdOut. Returns the error of f.
func ExecuteTimed(name string, f func() error) error {
	start := time.Now()
	err := f()
	elapsed := time.Since(start)

	// XXX(roosd) This string is used by buildkite to group output blocks.
	fmt.Printf("--- test results: %s\n", name)
	if err != nil {
		log.Error("Test failed", "name", name, "elapsed", elapsed)
		return err
	}
	log.Info("Test successful", "name", name, "elapsed", elapsed)
	return err
}

// ExtractUniqueDsts returns all unique destinations in pairs.
func ExtractUniqueDsts(pairs []IAPair) []*snet.UDPAddr {
	uniqueDsts := make(map[*snet.UDPAddr]bool)
	var res []*snet.UDPAddr
	for _, pair := range pairs {
		if !uniqueDsts[pair.Dst] {
			res = append(res, pair.Dst)
			uniqueDsts[pair.Dst] = true
		}
	}
	return res
}

// GroupBySource groups the ISD-AS pairs by source.
func GroupBySource(pairs []IAPair) map[*snet.UDPAddr][]*snet.UDPAddr {
	groups := make(map[*snet.UDPAddr][]*snet.UDPAddr)
	for _, pair := range pairs {
		groups[pair.Src] = append(groups[pair.Src], pair.Dst)
	}
	return groups
}

// RunUnaryTests runs the client for each IAPair.
// In case of an error the function is terminated immediately.
func RunUnaryTests(in Integration, pairs []IAPair,
	timeout time.Duration, checkOutput func([]byte) error) error {

	if timeout == 0 {
		timeout = DefaultRunTimeout
	}
	return runTests(in, pairs, 2, func(idx int, pair IAPair) error {
		log.Info(fmt.Sprintf("Test %v: %v -> %v (%v/%v)",
			in.Name(), pair.Src.IA, pair.Dst.IA, idx+1, len(pairs)))
		// Start client
		if err := RunClient(in, pair, timeout, checkOutput); err != nil {
			msg := fmt.Sprintf("Error in client: %v -> %v (%v/%v)",
				pair.Src.IA, pair.Dst.IA, idx+1, len(pairs))
			log.Error(msg, "name", in.Name(), "err", err)
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
			defer log.HandlePanic()
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

func GetSCIONDAddresses(networksFile string) (map[string]string, error) {
	b, err := os.ReadFile(networksFile)
	if err != nil {
		return nil, err
	}

	var networks map[string]string
	err = json.Unmarshal(b, &networks)
	if err != nil {
		return nil, err
	}
	return networks, nil
}

func GetSCIONDAddress(networksFile string, ia addr.IA) (string, error) {
	addresses, err := GetSCIONDAddresses(networksFile)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[%v]:%d", addresses[ia.String()], daemon.DefaultAPIPort), nil
}

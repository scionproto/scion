// Copyright 2021 Anapaya Systems
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

package path

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	snetpath "github.com/scionproto/scion/pkg/snet/path"
	"github.com/scionproto/scion/private/app/path/pathprobe"
	"github.com/scionproto/scion/private/path/pathpol"
)

// Sort sorts paths according to hops and interfaces.
func Sort(paths []snet.Path) {
	sort.Slice(paths, func(a, b int) bool {
		intfA, intfB := paths[a].Metadata().Interfaces, paths[b].Metadata().Interfaces
		// Sort according to path length.
		if len(intfA) != len(intfB) {
			return len(intfA) < len(intfB)
		}
		for i := range intfA {
			if iaA, iaB := intfA[i].IA, intfB[i].IA; iaA != iaB {
				return iaA < iaB
			}
			if idA, idB := intfA[i].ID, intfB[i].ID; idA != idB {
				return idA < idB
			}
		}
		expA, expB := paths[a].Metadata().Expiry, paths[b].Metadata().Expiry
		if !expA.Equal(expB) {
			return expA.Before(expB)
		}
		return true
	})
}

// Filter filters out paths according to a sequence.
func Filter(seq string, paths []snet.Path) ([]snet.Path, error) {
	s, err := pathpol.NewSequence(seq)
	if err != nil {
		return nil, err
	}
	return s.Eval(paths), nil
}

// Choose selects a path to the remote.
func Choose(
	ctx context.Context,
	conn daemon.Connector,
	remote addr.IA,
	opts ...Option,
) (snet.Path, error) {

	o := applyOption(opts)
	paths, err := fetchPaths(ctx, conn, remote, o.refresh, o.seq)
	if err != nil {
		return nil, serrors.Wrap("fetching paths", err)
	}
	if o.epic {
		// Only use paths that support EPIC and intra-AS (empty) paths.
		epicPaths := []snet.Path{}
		for _, p := range paths {
			if p.Metadata().EpicAuths.SupportsEpic() {
				epicPaths = append(epicPaths, p)
			}

			// Also include empty paths for AS internal communication.
			if _, isEmpty := p.Dataplane().(snetpath.Empty); isEmpty {
				epicPaths = append(epicPaths, p)
			}
		}
		if len(epicPaths) == 0 {
			return nil, serrors.New("no EPIC paths available")
		}
		paths = epicPaths
	}
	if o.probeCfg != nil {
		paths, err = filterUnhealthy(ctx, paths, remote, conn, o.probeCfg, o.epic)
		if err != nil {
			return nil, serrors.Wrap("probing paths", err)
		}
		if len(paths) == 0 {
			return nil, serrors.New("no healthy paths available")
		}
	}
	if o.interactive {
		return printAndChoose(paths, remote, o.colorScheme)
	}

	return paths[rand.Intn(len(paths))], nil
}

func filterUnhealthy(
	ctx context.Context,
	paths []snet.Path,
	remote addr.IA,
	sd daemon.Connector,
	cfg *ProbeConfig,
	epic bool,
) ([]snet.Path, error) {

	// Filter and save empty paths. They are considered healthy by definition, but must not be used
	// for path probing.
	var nonEmptyPaths []snet.Path
	var emptyPaths []snet.Path
	for _, path := range paths {
		if _, isEmpty := path.Dataplane().(snetpath.Empty); isEmpty {
			emptyPaths = append(emptyPaths, path)
			continue
		}
		nonEmptyPaths = append(nonEmptyPaths, path)
	}
	subCtx, cancelF := context.WithTimeout(ctx, 2*time.Second)
	defer cancelF()
	statuses, err := pathprobe.Prober{
		DstIA:                  remote,
		LocalIA:                cfg.LocalIA,
		LocalIP:                cfg.LocalIP,
		SCIONPacketConnMetrics: cfg.SCIONPacketConnMetrics,
		Topology:               sd,
	}.GetStatuses(subCtx, nonEmptyPaths, pathprobe.WithEPIC(epic))
	if err != nil {
		return nil, serrors.Wrap("probing paths", err)
	}
	// Filter all paths that aren't healthy.
	var healthyPaths []snet.Path
	for _, p := range paths {
		if status, ok := statuses[pathprobe.PathKey(p)]; ok &&
			status.Status == pathprobe.StatusAlive {
			healthyPaths = append(healthyPaths, p)
		}
	}
	// Append empty paths, since they are considered alive by definition.
	if len(emptyPaths) > 0 {
		healthyPaths = append(healthyPaths, emptyPaths...)
	}
	return healthyPaths, nil
}

func fetchPaths(
	ctx context.Context,
	conn daemon.Connector,
	remote addr.IA,
	refresh bool,
	seq string,
) ([]snet.Path, error) {

	allPaths, err := conn.Paths(ctx, remote, 0, daemon.PathReqFlags{Refresh: refresh})
	if err != nil {
		return nil, serrors.Wrap("retrieving paths", err)
	}

	paths, err := Filter(seq, allPaths)
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, serrors.New("no path available")
	}
	return paths, nil
}

func printAndChoose(paths []snet.Path, remote addr.IA, cs ColorScheme) (snet.Path, error) {
	Sort(paths)

	sectionHeader := func(intfs int) {
		cs.Header.Printf("%d Hops:\n", (intfs/2)+1)
	}

	fmt.Printf("Available paths to %s:\n", remote)
	sectionHeader(len(paths[0].Metadata().Interfaces))
	for i, path := range paths {
		if i != 0 && len(paths[i-1].Metadata().Interfaces) != len(path.Metadata().Interfaces) {
			sectionHeader(len(path.Metadata().Interfaces))
		}
		pathDesc := cs.KeyValues(
			"Hops", cs.Path(path),
			"MTU", fmt.Sprint(path.Metadata().MTU),
			"NextHop", fmt.Sprint(path.UnderlayNextHop()),
		)
		fmt.Printf("[%2d] %s\n", i, strings.Join(pathDesc, " "))
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("Choose path: ")
		pathIndexStr, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		idx, err := strconv.Atoi(pathIndexStr[:len(pathIndexStr)-1])
		if err == nil && idx < len(paths) {
			return paths[idx], nil
		}
		fmt.Fprintf(os.Stderr, "Path index outside of valid range: [0, %v]\n", len(paths)-1)
	}
}

// ColorScheme allows customizing the path coloring.
type ColorScheme struct {
	Header *color.Color
	Keys   *color.Color
	Values *color.Color
	Link   *color.Color
	Intf   *color.Color
	Good   *color.Color
	Bad    *color.Color
}

func DefaultColorScheme(disable bool) ColorScheme {
	if disable {
		noColor := color.New()
		return ColorScheme{
			Header: noColor,
			Keys:   noColor,
			Values: noColor,
			Link:   noColor,
			Intf:   noColor,
			Good:   noColor,
			Bad:    noColor,
		}
	}
	return ColorScheme{
		Header: color.New(color.FgHiBlack),
		Keys:   color.New(color.FgHiCyan),
		Values: color.New(),
		Link:   color.New(color.FgHiMagenta),
		Intf:   color.New(color.FgYellow),
		Good:   color.New(color.FgGreen),
		Bad:    color.New(color.FgRed),
	}
}

func (cs ColorScheme) KeyValue(k, v string) string {
	return fmt.Sprintf("%s: %s", cs.Keys.Sprint(k), cs.Values.Sprint(v))
}

func (cs ColorScheme) KeyValues(kv ...string) []string {
	if len(kv)%2 != 0 {
		panic("KeyValues expects even number of parameters")
	}
	entries := make([]string, 0, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		entries = append(entries, cs.KeyValue(kv[i], kv[i+1]))
	}
	return entries
}

func (cs ColorScheme) Path(path snet.Path) string {
	if path == nil {
		return ""
	}
	intfs := path.Metadata().Interfaces
	if len(intfs) == 0 {
		return ""
	}
	var hops []string
	intf := intfs[0]
	hops = append(hops, cs.Values.Sprintf("%s %s",
		cs.Values.Sprint(intf.IA),
		cs.Intf.Sprint(intf.ID),
	))
	for i := 1; i < len(intfs)-1; i += 2 {
		inIntf := intfs[i]
		outIntf := intfs[i+1]
		hops = append(hops, cs.Values.Sprintf("%s %s %s",
			cs.Intf.Sprint(inIntf.ID),
			cs.Values.Sprint(inIntf.IA),
			cs.Intf.Sprint(outIntf.ID),
		))
	}
	intf = intfs[len(intfs)-1]
	hops = append(hops, cs.Values.Sprintf("%s %s",
		cs.Intf.Sprint(intf.ID),
		cs.Values.Sprint(intf.IA),
	))
	return fmt.Sprintf("[%s]", strings.Join(hops, cs.Link.Sprintf(">")))
}

type ProbeConfig struct {
	LocalIA addr.IA
	LocalIP net.IP

	// Metrics injected into Prober.
	SCIONPacketConnMetrics snet.SCIONPacketConnMetrics
}

type options struct {
	interactive bool
	refresh     bool
	seq         string
	colorScheme ColorScheme
	probeCfg    *ProbeConfig
	epic        bool
}

type Option func(o *options)

func applyOption(opts []Option) options {
	var o options
	for _, option := range opts {
		option(&o)
	}
	return o
}

func WithInteractive(interactive bool) Option {
	return func(o *options) {
		o.interactive = interactive
	}
}

func WithRefresh(refresh bool) Option {
	return func(o *options) {
		o.refresh = refresh
	}
}

func WithSequence(seq string) Option {
	return func(o *options) {
		o.seq = seq
	}
}

func WithColorScheme(cs ColorScheme) Option {
	return func(o *options) {
		o.colorScheme = cs
	}
}

func WithProbing(cfg *ProbeConfig) Option {
	return func(o *options) {
		o.probeCfg = cfg
	}
}

func WithEPIC(epic bool) Option {
	return func(o *options) {
		o.epic = epic
	}
}

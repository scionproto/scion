// Copyright 2018 ETH Zurich, Anapaya Systems
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

package showpaths

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/private/common"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/private/app/path"
	"github.com/scionproto/scion/private/app/path/pathprobe"
	"github.com/scionproto/scion/private/path/pathpol"
)

// Result contains all the discovered paths.
type Result struct {
	LocalIA     addr.IA `json:"local_isd_as" yaml:"local_isd_as"`
	Destination addr.IA `json:"destination" yaml:"destination"`
	Paths       []Path  `json:"paths,omitempty" yaml:"paths,omitempty"`
}

// Path holds information about the discovered path.
type Path struct {
	FullPath    snet.Path       `json:"-" yaml:"-"`
	Fingerprint string          `json:"fingerprint" yaml:"fingerprint"`
	Hops        []Hop           `json:"hops" yaml:"hops"`
	Sequence    string          `json:"sequence" yaml:"sequence"`
	NextHop     string          `json:"next_hop" yaml:"next_hop"`
	Expiry      time.Time       `json:"expiry" yaml:"expiry"`
	MTU         uint16          `json:"mtu" yaml:"mtu"`
	Latency     []time.Duration `json:"latency" yaml:"latency"`
	Status      string          `json:"status,omitempty" yaml:"status,omitempty"`
	StatusInfo  string          `json:"status_info,omitempty" yaml:"status_info,omitempty"`
	Local       net.IP          `json:"local_ip,omitempty" yaml:"local_ip,omitempty"`
}

// Hop represents an hop on the path.
type Hop struct {
	IfID common.IFIDType `json:"ifid"`
	IA   addr.IA         `json:"isd_as"`
}

// Human writes human readable output to the writer.
func (r Result) Human(w io.Writer, showExtendedMetadata, colored bool) {
	cs := path.DefaultColorScheme(!colored)

	idxWidth := len(fmt.Sprint(len(r.Paths) - 1))

	// max number of key-value entries before switching to multi-line mode.
	// Chosen to allow to include the expiration date in a single line, but switch to multi-line
	// once at least one of the beacon extension items contains a meaningful value.
	const maxEntriesSingleline = 6
	separatorSingleline := " "
	// in multi-line mode, the entries are newline separated and indented,
	// taking into account the length of the path index "header" before the
	// first entry (length of index + 2 brackets + 1 space)
	separatorMultiline := "\n" + strings.Repeat(" ", idxWidth+2+1)

	sectionHeader := func(intfs int) {
		cs.Header.Fprintf(w, "%d Hops:\n", (intfs/2)+1)
	}
	sectionHeader(len(r.Paths[0].Hops))
	for i, path := range r.Paths {
		if i != 0 && len(r.Paths[i-1].Hops) != len(path.Hops) {
			sectionHeader(len(path.Hops))
		}

		entries := cs.KeyValues(
			"Hops", cs.Path(path.FullPath),
			"MTU", fmt.Sprint(path.MTU),
			"NextHop", fmt.Sprint(path.NextHop),
		)
		if showExtendedMetadata {
			meta := path.FullPath.Metadata()
			ttl := time.Until(path.Expiry).Truncate(time.Second)
			entries = append(entries, cs.KeyValue(
				"Expires", fmt.Sprintf("%s (%s)", path.Expiry, ttl),
			))
			// Add entries for information from beacon extension, only if a non-empty
			// value can be shown.
			entries = append(entries, filteredKeyValues(cs,
				"Latency", humanLatency(meta),
				"Bandwidth", humanBandwidth(meta),
				"Geo", humanGeo(meta, cs),
				"LinkType", humanLinkType(meta),
				"InternalHops", humanInternalHops(meta),
				"Notes", humanNotes(meta),
				"SupportsEPIC", strconv.FormatBool(meta.EpicAuths.SupportsEpic()),
			)...)
		}
		if path.Status != "" {
			statusColor := cs.Bad
			if strings.EqualFold(path.Status, string(pathprobe.StatusAlive)) {
				statusColor = cs.Good
			}
			entries = append(entries, cs.KeyValues(
				"Status", statusColor.Sprint(path.Status),
				"LocalIP", fmt.Sprint(path.Local),
			)...)
		}
		separator := separatorSingleline
		if len(entries) > maxEntriesSingleline {
			separator = separatorMultiline
		}
		fmt.Fprintf(w, "[%*d] %s\n", idxWidth, i, strings.Join(entries, separator))
	}
}

// filteredKeyValues is analogous to app.ColorScheme.KeyValues, but ignores
// entries with an empty value.
func filteredKeyValues(cs path.ColorScheme, kv ...string) []string {
	if len(kv)%2 != 0 {
		panic("KeyValues expects even number of parameters")
	}
	entries := make([]string, 0)
	for i := 0; i < len(kv); i += 2 {
		if kv[i+1] == "" {
			continue
		}
		entries = append(entries, cs.KeyValue(kv[i], kv[i+1]))
	}
	return entries
}

// humanLatency summarizes the latency information in the meta data in a human
// readable string. Returns empty string if no information is available.
func humanLatency(p *snet.PathMetadata) string {
	complete := true
	var tot time.Duration
	for _, v := range p.Latency {
		complete = complete && v >= 0
		if v >= 0 {
			tot += v
		}
	}
	if complete {
		return fmt.Sprint(tot)
	}
	if tot > 0 {
		return fmt.Sprintf(">%s (information incomplete)", tot)
	}
	return ""
}

// humanBandwidth summarizes the bandwidth information in the meta data in a
// human readable string. Returns empty string if no information is available.
func humanBandwidth(p *snet.PathMetadata) string {
	complete := true
	var bottleneck uint64 = math.MaxUint64
	for _, v := range p.Bandwidth {
		complete = complete && v > 0
		if v > 0 && v < bottleneck {
			bottleneck = v
		}
	}
	if complete {
		return fmt.Sprintf("%dKbit/s", bottleneck) // TODO(matzf) use appropriate metric prefixes?
	}
	if bottleneck < math.MaxUint64 {
		return fmt.Sprintf("%dKbit/s (information incomplete)", bottleneck)
	}
	return ""
}

// humanGeo summarizes the geographical information in the meta data in a human
// readable string. Returns empty string if no information is available.
func humanGeo(p *snet.PathMetadata, cs path.ColorScheme) string {
	geos := make([]string, len(p.Geo))
	hasAny := false
	for i, geo := range p.Geo {
		hasLatLong := (geo.Latitude != 0.0 || geo.Longitude != 0.0)
		latLong := fmt.Sprintf("%g,%g", geo.Latitude, geo.Longitude)
		sanitizedAddr := sanitizeString(geo.Address)
		quotedAddr := fmt.Sprintf("\"%s\"", sanitizedAddr)
		hasAddr := sanitizedAddr != ""
		hasAny = hasAny || hasLatLong || hasAddr
		if hasLatLong && hasAddr {
			geos[i] = fmt.Sprintf("%s (%s)", latLong, quotedAddr)
		} else if hasLatLong {
			geos[i] = latLong
		} else if hasAddr {
			geos[i] = quotedAddr
		} else {
			geos[i] = "N/A"
		}
	}
	if !hasAny { // special case to hide the Geo entry when no information is available
		return ""
	}
	return fmt.Sprintf("[%s]", strings.Join(geos, cs.Link.Sprintf(" > ")))
}

// humanGeo summarizes the link type information in the meta data in a human
// readable string. Returns empty string if no information is available.
func humanLinkType(p *snet.PathMetadata) string {
	hasAny := false
	for _, lt := range p.LinkType {
		if lt != snet.LinkTypeUnset {
			hasAny = true
			break
		}
	}
	if !hasAny {
		return ""
	}

	linkTypes := make([]string, len(p.LinkType))
	for i, lt := range p.LinkType {
		linkTypes[i] = lt.String()
	}
	return fmt.Sprintf("[%s]", strings.Join(linkTypes, ", "))
}

// humanInternalHops summarizes the information on the number of AS internal
// hops along the path in the meta data in a human readable string. Returns
// empty string if no information is available.
func humanInternalHops(p *snet.PathMetadata) string {
	internalHops := []string{}
	for i, numHops := range p.InternalHops {
		if numHops == 0 {
			continue
		}
		interfaceIdx := 2*i + 1
		ia := p.Interfaces[interfaceIdx].IA
		internalHops = append(internalHops, fmt.Sprintf("%s: %d", ia, numHops))
	}
	if len(internalHops) == 0 {
		return ""
	}
	return fmt.Sprintf("[%s]", strings.Join(internalHops, ", "))
}

// humanNotes summarizes the notes in the meta data in a human readable string.
// Returns empty string if no information is available.
func humanNotes(p *snet.PathMetadata) string {
	notes := []string{}
	for i, note := range p.Notes {
		if note == "" {
			continue
		}
		interfaceIdx := 0
		if i > 0 {
			interfaceIdx = 2*i - 1
		}
		ia := p.Interfaces[interfaceIdx].IA
		notes = append(notes, fmt.Sprintf("%s: \"%s\"", ia, sanitizeString(note)))
	}
	if len(notes) == 0 {
		return ""
	}
	return fmt.Sprintf("[%s]", strings.Join(notes, ", "))
}

// sanitizeString returns a trimmed single line representation of the string,
// with any control characters or quotation marks removed.
func sanitizeString(str string) string {
	str = strings.ReplaceAll(str, "\n", ", ")
	str = strings.TrimSpace(str)
	return strings.Map(func(r rune) rune {
		if r >= 32 && r != 127 && r != '"' {
			return r
		}
		return -1
	}, str)
}

// IsLocal returns true iff Source and Destination AS are identical
func (r Result) IsLocal() bool {
	return r.LocalIA == r.Destination
}

// Alive returns the number of alive paths.
func (r Result) Alive() int {
	var c int
	for _, path := range r.Paths {
		if strings.EqualFold(path.Status, string(pathprobe.StatusAlive)) {
			c++
		}
	}
	return c
}

// Run lists the paths to the specified ISD-AS to stdout.
func Run(ctx context.Context, dst addr.IA, cfg Config) (*Result, error) {
	sdConn, err := daemon.NewService(cfg.Daemon).Connect(ctx)
	if err != nil {
		return nil, serrors.WrapStr("connecting to the SCION Daemon", err, "addr", cfg.Daemon)
	}
	defer sdConn.Close()
	localIA, err := sdConn.LocalIA(ctx)
	if err != nil {
		return nil, serrors.WrapStr("determining local ISD-AS", err)
	}
	if dst == localIA {
		return &Result{
			LocalIA:     localIA,
			Destination: dst,
		}, nil
	}

	// TODO(lukedirtwalker): Replace this with snet.Router once we have the
	// possibility to have the same functionality, i.e. refresh, fetch all paths.
	// https://github.com/scionproto/scion/issues/3348
	allPaths, err := sdConn.Paths(ctx, dst, 0,
		daemon.PathReqFlags{Refresh: cfg.Refresh})
	if err != nil {
		return nil, serrors.WrapStr("retrieving paths from the SCION Daemon", err)
	}
	paths, err := path.Filter(cfg.Sequence, allPaths)
	if err != nil {
		return nil, err
	}
	if cfg.MaxPaths != 0 && len(paths) > cfg.MaxPaths {
		paths = paths[:cfg.MaxPaths]
	}

	// If the epic flag is set, filter all paths that do not have
	// the necessary epic authenticators.
	if cfg.Epic {
		epicPaths := []snet.Path{}
		for _, p := range paths {
			if p.Metadata().EpicAuths.SupportsEpic() {
				epicPaths = append(epicPaths, p)
			}
		}
		paths = epicPaths
	}

	var statuses map[string]pathprobe.Status
	if !cfg.NoProbe {
		p := pathprobe.FilterEmptyPaths(paths)
		statuses, err = pathprobe.Prober{
			DstIA:      dst,
			LocalIA:    localIA,
			LocalIP:    cfg.Local,
			ID:         uint16(rand.Uint32()),
			Dispatcher: cfg.Dispatcher,
		}.GetStatuses(ctx, p, pathprobe.WithEPIC(cfg.Epic))
		if err != nil {
			return nil, serrors.WrapStr("getting statuses", err)
		}
	}
	path.Sort(paths)
	res := &Result{
		LocalIA:     localIA,
		Destination: dst,
		Paths:       []Path{},
	}
	for _, path := range paths {
		fingerprint := "local"
		if len(path.Metadata().Interfaces) > 0 {
			fp := snet.Fingerprint(path).String()
			fingerprint = fp[:16]
		}
		var nextHop string
		if nh := path.UnderlayNextHop(); nh != nil {
			nextHop = path.UnderlayNextHop().String()
		}
		pathMeta := path.Metadata()
		rpath := Path{
			FullPath:    path,
			Fingerprint: fingerprint,
			NextHop:     nextHop,
			Expiry:      pathMeta.Expiry,
			MTU:         pathMeta.MTU,
			Latency:     pathMeta.Latency,
			Hops:        []Hop{},
		}
		for _, hop := range path.Metadata().Interfaces {
			rpath.Hops = append(rpath.Hops, Hop{IA: hop.IA, IfID: hop.ID})
		}
		if status, ok := statuses[pathprobe.PathKey(path)]; ok {
			rpath.Status = strings.ToLower(string(status.Status))
			rpath.StatusInfo = status.AdditionalInfo
			rpath.Local = status.LocalIP
		}
		seq, err := pathpol.GetSequence(path)
		rpath.Sequence = seq
		if err != nil {
			rpath.Sequence = "invalid"
		}
		res.Paths = append(res.Paths, rpath)
	}
	return res, nil
}

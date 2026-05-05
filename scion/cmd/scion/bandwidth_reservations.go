// Copyright 2026 SCION Association
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

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/private/topology"
)

type bandwidthReservationFlags struct {
	topologyPath   string
	staticInfo     string
	input          string
	output         string
	nonInteractive bool
}

type intraDomainLink struct {
	FromInterface iface.ID `json:"from_interface"`
	ToInterface   iface.ID `json:"to_interface"`
	FromRouter    string   `json:"from_router,omitempty"`
	ToRouter      string   `json:"to_router,omitempty"`
	BandwidthKbps uint64   `json:"bandwidth_kbit"`
}

type linkReservation struct {
	BandwidthKbps uint64    `json:"bandwidth_kbit"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
}

type reservedLink struct {
	Link         intraDomainLink   `json:"link"`
	Reservations []linkReservation `json:"reservations"`
}

type reservationFile struct {
	GeneratedAt      time.Time      `json:"generated_at"`
	TopologyFile     string         `json:"topology_file"`
	StaticInfoFile   string         `json:"static_info_file"`
	IntraDomainLinks []reservedLink `json:"intra_domain_links"`
}

func newBandwidthReservations(pather CommandPather) *cobra.Command {
	var flags bandwidthReservationFlags

	cmd := &cobra.Command{
		Use:   "bandwidth-reservations --topology topology.json --static-info staticInfoConfig.json --output reservations.json",
		Short: "Create bandwidth reservation slots for intra-domain links",
		Example: fmt.Sprintf(`  %[1]s bandwidth-reservations \
    --topology topology.json \
    --static-info staticInfoConfig.json \
    --output bandwidthReservations.json
  %[1]s bandwidth-reservations --topology topology.json --static-info staticInfoConfig.json \
    --input bandwidthReservations.json --output bandwidthReservations.json
  %[1]s bandwidth-reservations --topology topology.json --static-info staticInfoConfig.json \
    --input bandwidthReservations.json --non-interactive`, pather.CommandPath()),
		Long: `'bandwidth-reservations' reads a topology.json file and a staticInfoConfig.json
file, lists all intra-domain links described by staticInfoConfig.json Bandwidth
Intra entries, and stores user-entered reservation slots in a JSON file.

Reservation bandwidth values use the same unit as staticInfoConfig.json bandwidth
values: Kbit/s.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runBandwidthReservations(cmd.InOrStdin(), cmd.OutOrStdout(), flags)
		},
	}
	cmd.Flags().StringVarP(&flags.topologyPath, "topology", "t", "", "Path to topology.json")
	cmd.Flags().StringVarP(&flags.staticInfo, "static-info", "s", "", "Path to staticInfoConfig.json")
	cmd.Flags().StringVarP(&flags.input, "input", "i", "", "Path to read existing reservation JSON")
	cmd.Flags().StringVarP(&flags.output, "output", "o", "", "Path to write reservation JSON")
	cmd.Flags().BoolVar(&flags.nonInteractive, "non-interactive", false,
		"List links and reservations without prompting or writing an output file")
	cmd.MarkFlagRequired("topology")
	cmd.MarkFlagRequired("static-info")
	return cmd
}

func runBandwidthReservations(in io.Reader, out io.Writer, flags bandwidthReservationFlags) error {
	if flags.topologyPath == "" {
		return serrors.New("topology path is required")
	}
	if flags.staticInfo == "" {
		return serrors.New("static info config path is required")
	}
	if !flags.nonInteractive && flags.output == "" {
		return serrors.New("output path is required")
	}

	topo, err := topology.RWTopologyFromJSONFile(flags.topologyPath)
	if err != nil {
		return serrors.Wrap("loading topology", err, "file", flags.topologyPath)
	}
	staticInfo, err := beaconing.ParseStaticInfoCfg(flags.staticInfo)
	if err != nil {
		return err
	}

	links := intraDomainLinks(topo, staticInfo)
	reserved := newReservationLinks(links)
	if flags.input != "" {
		existing, err := readReservationFile(flags.input)
		if err != nil {
			return err
		}
		reserved = mergeReservationLinks(reserved, existing.IntraDomainLinks)
	}
	if err := validateReservationLinks(reserved); err != nil {
		return err
	}

	printReservationLinks(out, reserved)
	if flags.nonInteractive {
		return nil
	}

	if err := promptReservations(bufio.NewReader(in), out, reserved); err != nil {
		return err
	}
	if err := validateReservationLinks(reserved); err != nil {
		return err
	}

	result := reservationFile{
		GeneratedAt:      time.Now().UTC(),
		TopologyFile:     flags.topologyPath,
		StaticInfoFile:   flags.staticInfo,
		IntraDomainLinks: reserved,
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return serrors.Wrap("marshalling reservations", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(flags.output, raw, 0o644); err != nil {
		return serrors.Wrap("writing reservations", err, "file", flags.output)
	}
	fmt.Fprintf(out, "Wrote reservations to %s\n", flags.output)
	return nil
}

func readReservationFile(path string) (*reservationFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, serrors.Wrap("reading reservations", err, "file", path)
	}
	var file reservationFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, serrors.Wrap("parsing reservations", err, "file", path)
	}
	for i := range file.IntraDomainLinks {
		if file.IntraDomainLinks[i].Reservations == nil {
			file.IntraDomainLinks[i].Reservations = []linkReservation{}
		}
	}
	return &file, nil
}

func newReservationLinks(links []intraDomainLink) []reservedLink {
	reserved := make([]reservedLink, 0, len(links))
	for _, link := range links {
		reserved = append(reserved, reservedLink{
			Link:         link,
			Reservations: []linkReservation{},
		})
	}
	return reserved
}

func mergeReservationLinks(current, existing []reservedLink) []reservedLink {
	byKey := make(map[linkKey][]linkReservation, len(existing))
	matched := make(map[linkKey]bool, len(existing))
	for _, link := range existing {
		byKey[makeLinkKey(link.Link)] = append(byKey[makeLinkKey(link.Link)], link.Reservations...)
	}
	for i := range current {
		key := makeLinkKey(current[i].Link)
		current[i].Reservations = append(current[i].Reservations,
			byKey[key]...)
		sortReservations(current[i].Reservations)
		matched[key] = true
	}
	for _, link := range existing {
		key := makeLinkKey(link.Link)
		if matched[key] {
			continue
		}
		if link.Reservations == nil {
			link.Reservations = []linkReservation{}
		}
		sortReservations(link.Reservations)
		current = append(current, link)
	}
	return current
}

func printReservationLinks(out io.Writer, links []reservedLink) {
	fmt.Fprintf(out, "Intra-domain links (%d):\n", len(links))
	for i, link := range links {
		fmt.Fprintf(out, "  [%d] if%d (%s) <-> if%d (%s), bandwidth %d Kbit/s\n",
			i+1, link.Link.FromInterface, link.Link.FromRouter, link.Link.ToInterface,
			link.Link.ToRouter, link.Link.BandwidthKbps)
		if len(link.Reservations) == 0 {
			fmt.Fprintln(out, "      no reservations")
			continue
		}
		for j, reservation := range link.Reservations {
			fmt.Fprintf(out, "      [%d] %d Kbit/s, %s to %s\n",
				j+1, reservation.BandwidthKbps,
				reservation.Start.Format(time.RFC3339),
				reservation.End.Format(time.RFC3339))
		}
	}
}

func intraDomainLinks(topo *topology.RWTopology, staticInfo *beaconing.StaticInfoCfg) []intraDomainLink {
	type pair struct {
		a iface.ID
		b iface.ID
	}
	linksByPair := make(map[pair]intraDomainLink)
	for from, bandwidths := range staticInfo.Bandwidth {
		if _, ok := topo.IFInfoMap[from]; !ok {
			continue
		}
		for to, bandwidth := range bandwidths.Intra {
			if _, ok := topo.IFInfoMap[to]; !ok {
				continue
			}
			if from == to {
				continue
			}
			p := pair{a: from, b: to}
			if p.a > p.b {
				p.a, p.b = p.b, p.a
			}
			if existing, ok := linksByPair[p]; ok && existing.BandwidthKbps <= bandwidth {
				continue
			}
			fromInfo := topo.IFInfoMap[p.a]
			toInfo := topo.IFInfoMap[p.b]
			linksByPair[p] = intraDomainLink{
				FromInterface: p.a,
				ToInterface:   p.b,
				FromRouter:    fromInfo.BRName,
				ToRouter:      toInfo.BRName,
				BandwidthKbps: bandwidth,
			}
		}
	}
	links := make([]intraDomainLink, 0, len(linksByPair))
	for _, link := range linksByPair {
		links = append(links, link)
	}
	sort.Slice(links, func(i, j int) bool {
		if links[i].FromInterface != links[j].FromInterface {
			return links[i].FromInterface < links[j].FromInterface
		}
		return links[i].ToInterface < links[j].ToInterface
	})
	return links
}

type linkKey struct {
	a iface.ID
	b iface.ID
}

func makeLinkKey(link intraDomainLink) linkKey {
	key := linkKey{a: link.FromInterface, b: link.ToInterface}
	if key.a > key.b {
		key.a, key.b = key.b, key.a
	}
	return key
}

func validateReservationLinks(links []reservedLink) error {
	for _, link := range links {
		if err := validateLinkReservations(link); err != nil {
			return err
		}
	}
	return nil
}

func validateLinkReservations(link reservedLink) error {
	for _, reservation := range link.Reservations {
		if reservation.BandwidthKbps == 0 {
			return serrors.New("reservation bandwidth must be positive",
				"from_interface", link.Link.FromInterface,
				"to_interface", link.Link.ToInterface)
		}
		if !reservation.End.After(reservation.Start) {
			return serrors.New("reservation end time must be after start time",
				"from_interface", link.Link.FromInterface,
				"to_interface", link.Link.ToInterface,
				"start", reservation.Start,
				"end", reservation.End)
		}
	}

	type event struct {
		at        time.Time
		bandwidth int64
	}
	events := make([]event, 0, len(link.Reservations)*2)
	for _, reservation := range link.Reservations {
		events = append(events,
			event{at: reservation.Start, bandwidth: int64(reservation.BandwidthKbps)},
			event{at: reservation.End, bandwidth: -int64(reservation.BandwidthKbps)},
		)
	}
	sort.Slice(events, func(i, j int) bool {
		if !events[i].at.Equal(events[j].at) {
			return events[i].at.Before(events[j].at)
		}
		return events[i].bandwidth < events[j].bandwidth
	})

	var active int64
	for _, event := range events {
		active += event.bandwidth
		if active > int64(link.Link.BandwidthKbps) {
			return serrors.New("reservations exceed link bandwidth",
				"from_interface", link.Link.FromInterface,
				"to_interface", link.Link.ToInterface,
				"reserved_kbit", active,
				"link_bandwidth_kbit", link.Link.BandwidthKbps,
				"time", event.at)
		}
	}
	return nil
}

func promptReservations(in *bufio.Reader, out io.Writer, links []reservedLink) error {
	for {
		fmt.Fprint(out, "\nSelect link number to add a reservation, or press Enter to finish: ")
		raw, err := readLine(in)
		if err != nil {
			return err
		}
		if raw == "" {
			return nil
		}
		selected, err := strconv.Atoi(raw)
		if err != nil || selected < 1 || selected > len(links) {
			fmt.Fprintf(out, "Enter a link number between 1 and %d.\n", len(links))
			continue
		}
		i := selected - 1
		link := links[i].Link
		fmt.Fprintf(out, "Adding reservation for if%d <-> if%d.\n",
			link.FromInterface, link.ToInterface)
		for {
			reservation, err := promptReservation(in, out)
			if err != nil {
				return err
			}
			candidate := append(append([]linkReservation{}, links[i].Reservations...), reservation)
			sortReservations(candidate)
			if err := validateLinkReservations(reservedLink{
				Link:         links[i].Link,
				Reservations: candidate,
			}); err != nil {
				fmt.Fprintf(out, "  Reservation rejected: %s\n", err)
				break
			}
			links[i].Reservations = candidate
			fmt.Fprintln(out)
			printReservationLinks(out, links)
			break
		}
	}
}

func sortReservations(reservations []linkReservation) {
	sort.Slice(reservations, func(i, j int) bool {
		if !reservations[i].Start.Equal(reservations[j].Start) {
			return reservations[i].Start.Before(reservations[j].Start)
		}
		return reservations[i].End.Before(reservations[j].End)
	})
}

func promptReservation(in *bufio.Reader, out io.Writer) (linkReservation, error) {
	var reservation linkReservation
	for {
		fmt.Fprint(out, "  Bandwidth reservation in Kbit/s: ")
		raw, err := readLine(in)
		if err != nil {
			return reservation, err
		}
		bandwidth, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || bandwidth == 0 {
			fmt.Fprintln(out, "  Enter a positive integer bandwidth.")
			continue
		}
		reservation.BandwidthKbps = bandwidth
		break
	}
	for {
		fmt.Fprint(out, "  Start time (RFC3339, YYYY-MM-DD, YYYY-MM-DD HH:MM[:SS]): ")
		raw, err := readLine(in)
		if err != nil {
			return reservation, err
		}
		start, err := parseReservationTime(raw, startOfDay)
		if err != nil {
			fmt.Fprintln(out, "  Enter a valid start time.")
			continue
		}
		reservation.Start = start
		break
	}
	for {
		fmt.Fprint(out, "  End time (RFC3339, YYYY-MM-DD, YYYY-MM-DD HH:MM[:SS]): ")
		raw, err := readLine(in)
		if err != nil {
			return reservation, err
		}
		end, err := parseReservationTime(raw, endOfDay)
		if err != nil {
			fmt.Fprintln(out, "  Enter a valid end time.")
			continue
		}
		if !end.After(reservation.Start) {
			fmt.Fprintln(out, "  End time must be after start time.")
			continue
		}
		reservation.End = end
		break
	}
	return reservation, nil
}

type defaultTimeOfDay int

const (
	startOfDay defaultTimeOfDay = iota
	endOfDay
)

func parseReservationTime(raw string, defaultTime defaultTimeOfDay) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, serrors.New("empty time")
	}
	if t, err := time.ParseInLocation("2006-01-02", raw, time.Local); err == nil {
		switch defaultTime {
		case startOfDay:
			return t, nil
		case endOfDay:
			return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 39, 0, time.Local), nil
		default:
			return time.Time{}, serrors.New("unknown default time")
		}
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02 15:04",
		"2006-01-02 15:04:05",
	} {
		if layout == time.RFC3339 {
			t, err := time.Parse(layout, raw)
			if err == nil {
				return t, nil
			}
			continue
		}
		t, err := time.ParseInLocation(layout, raw, time.Local)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, serrors.New("invalid time", "time", raw)
}

func readLine(in *bufio.Reader) (string, error) {
	raw, err := in.ReadString('\n')
	if err != nil && !(err == io.EOF && raw != "") {
		return "", err
	}
	return strings.TrimSpace(raw), nil
}

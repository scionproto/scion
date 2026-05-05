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

type bandwidthAssetFlags struct {
	topologyPath   string
	staticInfo     string
	input          string
	output         string
	nonInteractive bool
}

type intraDomainLink struct {
	FromInterface iface.ID `json:"from_interface"`
	ToInterface   iface.ID `json:"to_interface"`
	BandwidthKbps uint64   `json:"bandwidth_kbit"`
}

type linkAsset struct {
	BandwidthKbps uint64    `json:"bandwidth_kbit"`
	Start         time.Time `json:"start"`
	End           time.Time `json:"end"`
}

type assetLink struct {
	Link   intraDomainLink `json:"link"`
	Assets []linkAsset     `json:"assets"`
}

type assetFile struct {
	GeneratedAt      time.Time   `json:"generated_at"`
	TopologyFile     string      `json:"topology_file"`
	StaticInfoFile   string      `json:"static_info_file"`
	BWGranularity    uint64      `json:"bw_granularity"`
	TimeGranularity  uint64      `json:"time_granularity"`
	IntraDomainLinks []assetLink `json:"intra_domain_links"`
}

func newBandwidthAssets(pather CommandPather) *cobra.Command {
	var flags bandwidthAssetFlags

	cmd := &cobra.Command{
		Use:   "bandwidth-assets --topology topology.json --static-info staticInfoConfig.json --output assets.json",
		Short: "Create bandwidth asset slots for intra-domain links",
		Example: fmt.Sprintf(`  %[1]s bandwidth-assets \
    --topology topology.json \
    --static-info staticInfoConfig.json \
    --output bandwidthAssets.json
  %[1]s bandwidth-assets --topology topology.json --static-info staticInfoConfig.json \
    --input bandwidthAssets.json --output bandwidthAssets.json
  %[1]s bandwidth-assets --topology topology.json --static-info staticInfoConfig.json \
    --input bandwidthAssets.json --non-interactive`, pather.CommandPath()),
		Long: `'bandwidth-assets' reads a topology.json file and a staticInfoConfig.json
file, lists all intra-domain links described by staticInfoConfig.json Bandwidth
Intra entries, and stores user-entered asset slots in a JSON file.

Asset bandwidth values use the same unit as staticInfoConfig.json bandwidth
values: Kbit/s.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.SilenceUsage = true
			return runBandwidthAssets(cmd.InOrStdin(), cmd.OutOrStdout(), flags)
		},
	}
	cmd.Flags().StringVarP(&flags.topologyPath, "topology", "t", "", "Path to topology.json")
	cmd.Flags().StringVarP(&flags.staticInfo, "static-info", "s", "", "Path to staticInfoConfig.json")
	cmd.Flags().StringVarP(&flags.input, "input", "i", "", "Path to read existing asset JSON")
	cmd.Flags().StringVarP(&flags.output, "output", "o", "", "Path to write asset JSON")
	cmd.Flags().BoolVar(&flags.nonInteractive, "non-interactive", false,
		"List links and assets without prompting or writing an output file")
	cmd.MarkFlagRequired("topology")
	cmd.MarkFlagRequired("static-info")
	return cmd
}

func runBandwidthAssets(in io.Reader, out io.Writer, flags bandwidthAssetFlags) error {
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
	assetLinks := newAssetLinks(links)
	bwGranularity := uint64(1)
	timeGranularity := uint64(1)
	if flags.input != "" {
		existing, err := readAssetFile(flags.input)
		if err != nil {
			return err
		}
		bwGranularity = existing.BWGranularity
		timeGranularity = existing.TimeGranularity
		assetLinks = mergeAssetLinks(assetLinks, existing.IntraDomainLinks)
	}
	if err := validateAssetLinks(assetLinks); err != nil {
		return err
	}

	printAssetLinks(out, assetLinks, bwGranularity, timeGranularity)
	if flags.nonInteractive {
		return nil
	}

	if err := promptAssets(bufio.NewReader(in), out, assetLinks,
		&bwGranularity, &timeGranularity); err != nil {
		return err
	}
	if err := validateAssetLinks(assetLinks); err != nil {
		return err
	}

	result := assetFile{
		GeneratedAt:      time.Now().UTC(),
		TopologyFile:     flags.topologyPath,
		StaticInfoFile:   flags.staticInfo,
		BWGranularity:    bwGranularity,
		TimeGranularity:  timeGranularity,
		IntraDomainLinks: assetLinks,
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return serrors.Wrap("marshalling assets", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(flags.output, raw, 0o644); err != nil {
		return serrors.Wrap("writing assets", err, "file", flags.output)
	}
	fmt.Fprintf(out, "Wrote assets to %s\n", flags.output)
	return nil
}

func readAssetFile(path string) (*assetFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, serrors.Wrap("reading assets", err, "file", path)
	}
	var file assetFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, serrors.Wrap("parsing assets", err, "file", path)
	}
	if file.BWGranularity == 0 {
		file.BWGranularity = 1
	}
	if file.TimeGranularity == 0 {
		file.TimeGranularity = 1
	}
	for i := range file.IntraDomainLinks {
		if file.IntraDomainLinks[i].Assets == nil {
			file.IntraDomainLinks[i].Assets = []linkAsset{}
		}
	}
	return &file, nil
}

func newAssetLinks(links []intraDomainLink) []assetLink {
	assetLinks := make([]assetLink, 0, len(links))
	for _, link := range links {
		assetLinks = append(assetLinks, assetLink{
			Link:   link,
			Assets: []linkAsset{},
		})
	}
	return assetLinks
}

func mergeAssetLinks(current, existing []assetLink) []assetLink {
	byKey := make(map[linkKey][]linkAsset, len(existing))
	matched := make(map[linkKey]bool, len(existing))
	for _, link := range existing {
		byKey[makeLinkKey(link.Link)] = append(byKey[makeLinkKey(link.Link)], link.Assets...)
	}
	for i := range current {
		key := makeLinkKey(current[i].Link)
		current[i].Assets = append(current[i].Assets,
			byKey[key]...)
		sortAssets(current[i].Assets)
		matched[key] = true
	}
	for _, link := range existing {
		key := makeLinkKey(link.Link)
		if matched[key] {
			continue
		}
		if link.Assets == nil {
			link.Assets = []linkAsset{}
		}
		sortAssets(link.Assets)
		current = append(current, link)
	}
	return current
}

func printAssetLinks(out io.Writer, links []assetLink,
	bwGranularity, timeGranularity uint64) {
	fmt.Fprintf(out, "Granularity: bw_granularity %d Kbit/s, time_granularity %d second(s)\n",
		bwGranularity, timeGranularity)
	fmt.Fprintf(out, "Intra-domain links (%d):\n", len(links))
	for i, link := range links {
		fmt.Fprintf(out, "  [%d] %d <-> %d, bandwidth %d Kbit/s\n",
			i+1, link.Link.FromInterface, link.Link.ToInterface,
			link.Link.BandwidthKbps)
		if len(link.Assets) == 0 {
			fmt.Fprintln(out, "      no assets")
			continue
		}
		for j, asset := range link.Assets {
			fmt.Fprintf(out, "      [%d] %d Kbit/s, %s to %s\n",
				j+1, asset.BandwidthKbps,
				asset.Start.Format(time.RFC3339),
				asset.End.Format(time.RFC3339))
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
			linksByPair[p] = intraDomainLink{
				FromInterface: p.a,
				ToInterface:   p.b,
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

func validateAssetLinks(links []assetLink) error {
	for _, link := range links {
		if err := validateLinkAssets(link); err != nil {
			return err
		}
	}
	return nil
}

func validateLinkAssets(link assetLink) error {
	assets := append([]linkAsset{}, link.Assets...)
	sortAssets(assets)
	for _, asset := range assets {
		if asset.BandwidthKbps == 0 {
			return serrors.New("asset bandwidth must be positive",
				"from_interface", link.Link.FromInterface,
				"to_interface", link.Link.ToInterface)
		}
		if !asset.End.After(asset.Start) {
			return serrors.New("asset end time must be after start time",
				"from_interface", link.Link.FromInterface,
				"to_interface", link.Link.ToInterface,
				"start", asset.Start,
				"end", asset.End)
		}
	}
	for i := 1; i < len(assets); i++ {
		if assets[i-1].End.After(assets[i].Start) {
			return serrors.New("assets overlap on link",
				"from_interface", link.Link.FromInterface,
				"to_interface", link.Link.ToInterface,
				"first_start", assets[i-1].Start,
				"first_end", assets[i-1].End,
				"second_start", assets[i].Start,
				"second_end", assets[i].End)
		}
	}
	return nil
}

func promptAssets(in *bufio.Reader, out io.Writer, links []assetLink,
	bwGranularity, timeGranularity *uint64) error {
	for {
		fmt.Fprint(out, "\nSelect link number to add an asset, 'b' for bandwidth granularity, "+
			"'t' for time granularity, or press Enter to finish: ")
		raw, err := readLine(in)
		if err != nil {
			return err
		}
		if raw == "" {
			return nil
		}
		switch strings.ToLower(raw) {
		case "b":
			if err := promptGranularity(in, out, "bandwidth", bwGranularity); err != nil {
				return err
			}
			continue
		case "t":
			if err := promptGranularity(in, out, "time", timeGranularity); err != nil {
				return err
			}
			continue
		}
		selected, err := strconv.Atoi(raw)
		if err != nil || selected < 1 || selected > len(links) {
			fmt.Fprintf(out, "Enter a link number between 1 and %d.\n", len(links))
			continue
		}
		i := selected - 1
		link := links[i].Link
		fmt.Fprintf(out, "Adding asset for %d <-> %d.\n",
			link.FromInterface, link.ToInterface)
		for {
			asset, err := promptAsset(in, out)
			if err != nil {
				return err
			}
			if err := validateAssetGranularity(asset,
				*bwGranularity, *timeGranularity); err != nil {
				fmt.Fprintf(out, "  Asset rejected: %s\n", err)
				break
			}
			candidate := append(append([]linkAsset{}, links[i].Assets...), asset)
			sortAssets(candidate)
			if err := validateLinkAssets(assetLink{
				Link:   links[i].Link,
				Assets: candidate,
			}); err != nil {
				fmt.Fprintf(out, "  Asset rejected: %s\n", err)
				break
			}
			links[i].Assets = candidate
			fmt.Fprintln(out)
			printAssetLinks(out, links, *bwGranularity, *timeGranularity)
			break
		}
	}
}

func promptGranularity(in *bufio.Reader, out io.Writer, name string, value *uint64) error {
	for {
		fmt.Fprintf(out, "  %s granularity: ", name)
		raw, err := readLine(in)
		if err != nil {
			return err
		}
		granularity, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || granularity == 0 {
			fmt.Fprintln(out, "  Enter a positive integer granularity.")
			continue
		}
		*value = granularity
		return nil
	}
}

func validateAssetGranularity(asset linkAsset,
	bwGranularity, timeGranularity uint64) error {
	if bwGranularity == 0 {
		bwGranularity = 1
	}
	if timeGranularity == 0 {
		timeGranularity = 1
	}
	if asset.BandwidthKbps%bwGranularity != 0 {
		return serrors.New("asset bandwidth is not a multiple of bandwidth granularity",
			"bandwidth_kbit", asset.BandwidthKbps,
			"bw_granularity", bwGranularity)
	}
	duration := asset.End.Sub(asset.Start)
	if duration <= 0 {
		return serrors.New("asset duration must be positive")
	}
	if duration%time.Second != 0 {
		return serrors.New("asset duration must be a whole number of seconds",
			"duration", duration)
	}
	durationSeconds := uint64(duration / time.Second)
	if durationSeconds%timeGranularity != 0 {
		return serrors.New("asset duration is not a multiple of time granularity",
			"duration_seconds", durationSeconds,
			"time_granularity", timeGranularity)
	}
	return nil
}

func sortAssets(assets []linkAsset) {
	sort.Slice(assets, func(i, j int) bool {
		if !assets[i].Start.Equal(assets[j].Start) {
			return assets[i].Start.Before(assets[j].Start)
		}
		return assets[i].End.Before(assets[j].End)
	})
}

func promptAsset(in *bufio.Reader, out io.Writer) (linkAsset, error) {
	var asset linkAsset
	for {
		fmt.Fprint(out, "  Bandwidth asset in Kbit/s: ")
		raw, err := readLine(in)
		if err != nil {
			return asset, err
		}
		bandwidth, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || bandwidth == 0 {
			fmt.Fprintln(out, "  Enter a positive integer bandwidth.")
			continue
		}
		asset.BandwidthKbps = bandwidth
		break
	}
	for {
		fmt.Fprint(out, "  Start time (RFC3339, YYYY-MM-DD, YYYY-MM-DD HH:MM[:SS]): ")
		raw, err := readLine(in)
		if err != nil {
			return asset, err
		}
		start, err := parseAssetTime(raw, startOfDay)
		if err != nil {
			fmt.Fprintln(out, "  Enter a valid start time.")
			continue
		}
		asset.Start = start
		break
	}
	for {
		fmt.Fprint(out, "  End time (RFC3339, YYYY-MM-DD, YYYY-MM-DD HH:MM[:SS]): ")
		raw, err := readLine(in)
		if err != nil {
			return asset, err
		}
		end, err := parseAssetTime(raw, endOfDay)
		if err != nil {
			fmt.Fprintln(out, "  Enter a valid end time.")
			continue
		}
		if !end.After(asset.Start) {
			fmt.Fprintln(out, "  End time must be after start time.")
			continue
		}
		asset.End = end
		break
	}
	return asset, nil
}

type defaultTimeOfDay int

const (
	startOfDay defaultTimeOfDay = iota
	endOfDay
)

func parseAssetTime(raw string, defaultTime defaultTimeOfDay) (time.Time, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, serrors.New("empty time")
	}
	if t, err := time.ParseInLocation("2006-01-02", raw, time.Local); err == nil {
		switch defaultTime {
		case startOfDay:
			return t, nil
		case endOfDay:
			return time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.Local), nil
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

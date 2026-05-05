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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scionproto/scion/control/beaconing"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/private/topology"
)

type testPather string

func (p testPather) CommandPath() string {
	return string(p)
}

func TestNewBandwidthAssetsCommandUsesRenamedTool(t *testing.T) {
	cmd := newBandwidthAssets(testPather("scion"))
	if !strings.HasPrefix(cmd.Use, "bandwidth-assets ") {
		t.Fatalf("unexpected command use: %q", cmd.Use)
	}
	oldCommand := "bandwidth-" + "reser" + "vations"
	oldTerm := "reser" + "vations"
	for _, text := range []string{cmd.Example, cmd.Long} {
		if strings.Contains(text, oldCommand) || strings.Contains(text, oldTerm) {
			t.Fatalf("command text still uses old terminology: %q", text)
		}
	}
}

func TestIntraDomainLinks(t *testing.T) {
	topo := &topology.RWTopology{
		IFInfoMap: topology.IfInfoMap{
			1: {BRName: "br1"},
			2: {BRName: "br2"},
			3: {BRName: "br3"},
		},
	}
	staticInfo := &beaconing.StaticInfoCfg{
		Bandwidth: map[iface.ID]beaconing.InterfaceBandwidths{
			1: {Intra: map[iface.ID]uint64{2: 100, 4: 400}},
			2: {Intra: map[iface.ID]uint64{1: 90, 3: 200}},
			3: {Intra: map[iface.ID]uint64{3: 300}},
		},
	}

	links := intraDomainLinks(topo, staticInfo)
	if len(links) != 2 {
		t.Fatalf("unexpected link count: got %d want 2", len(links))
	}
	if links[0].FromInterface != 1 || links[0].ToInterface != 2 {
		t.Fatalf("unexpected first link: %+v", links[0])
	}
	if links[0].BandwidthKbps != 90 {
		t.Fatalf("unexpected conservative bandwidth: got %d want 90", links[0].BandwidthKbps)
	}
	if links[1].FromInterface != 2 || links[1].ToInterface != 3 {
		t.Fatalf("unexpected second link: %+v", links[1])
	}
}

func TestParseAssetTime(t *testing.T) {
	rfc3339, err := parseAssetTime("2026-05-05T12:30:00Z", startOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if !rfc3339.Equal(time.Date(2026, 5, 5, 12, 30, 0, 0, time.UTC)) {
		t.Fatalf("unexpected RFC3339 time: %s", rfc3339)
	}

	local, err := parseAssetTime("2026-05-05 12:30", startOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if local.Location() != time.Local {
		t.Fatalf("unexpected location: got %s want %s", local.Location(), time.Local)
	}

	withSeconds, err := parseAssetTime("2026-05-05 12:30:45", startOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if withSeconds.Second() != 45 {
		t.Fatalf("unexpected seconds: got %d want 45", withSeconds.Second())
	}

	startDefault, err := parseAssetTime("2026-05-05", startOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if startDefault.Hour() != 0 || startDefault.Minute() != 0 || startDefault.Second() != 0 {
		t.Fatalf("unexpected start default: %s", startDefault)
	}

	endDefault, err := parseAssetTime("2026-05-05", endOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if endDefault.Hour() != 23 || endDefault.Minute() != 59 || endDefault.Second() != 59 {
		t.Fatalf("unexpected end default: %s", endDefault)
	}

	if _, err := parseAssetTime("not a time", startOfDay); err == nil {
		t.Fatal("expected invalid time error")
	}
}

func TestValidateLinkAssetsRejectsOverlappingAssets(t *testing.T) {
	link := assetLink{
		Link: intraDomainLink{
			FromInterface: 1,
			ToInterface:   2,
			BandwidthKbps: 100,
		},
		Assets: []linkAsset{
			{
				BandwidthKbps: 60,
				Start:         time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 5, 11, 0, 0, 0, time.UTC),
			},
			{
				BandwidthKbps: 30,
				Start:         time.Date(2026, 5, 5, 10, 30, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 5, 11, 30, 0, 0, time.UTC),
			},
		},
	}

	if err := validateLinkAssets(link); err == nil {
		t.Fatal("expected overlapping assets error")
	}
}

func TestValidateLinkAssetsAllowsAdjacentAssets(t *testing.T) {
	link := assetLink{
		Link: intraDomainLink{
			FromInterface: 1,
			ToInterface:   2,
			BandwidthKbps: 100,
		},
		Assets: []linkAsset{
			{
				BandwidthKbps: 100,
				Start:         time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 5, 11, 0, 0, 0, time.UTC),
			},
			{
				BandwidthKbps: 100,
				Start:         time.Date(2026, 5, 5, 11, 0, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC),
			},
		},
	}

	if err := validateLinkAssets(link); err != nil {
		t.Fatal(err)
	}
}

func TestReadExistingAssetFileAndMerge(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "assets.json")
	existing := assetFile{
		BWGranularity:   5,
		TimeGranularity: 60,
		IntraDomainLinks: []assetLink{
			{
				Link: intraDomainLink{FromInterface: 2, ToInterface: 1},
				Assets: []linkAsset{{
					BandwidthKbps: 40,
					Start:         time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
					End:           time.Date(2026, 5, 5, 11, 0, 0, 0, time.UTC),
				}},
			},
		},
	}
	raw, err := json.Marshal(existing)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input, raw, 0o644); err != nil {
		t.Fatal(err)
	}

	loaded, err := readAssetFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BWGranularity != 5 || loaded.TimeGranularity != 60 {
		t.Fatalf("unexpected granularity: bw %d time %d",
			loaded.BWGranularity, loaded.TimeGranularity)
	}
	current := newAssetLinks([]intraDomainLink{{
		FromInterface: 1,
		ToInterface:   2,
		BandwidthKbps: 100,
	}})
	merged := mergeAssetLinks(current, loaded.IntraDomainLinks)

	if len(merged[0].Assets) != 1 {
		t.Fatalf("unexpected asset count: got %d want 1", len(merged[0].Assets))
	}
	if merged[0].Assets[0].BandwidthKbps != 40 {
		t.Fatalf("unexpected asset bandwidth: got %d want 40",
			merged[0].Assets[0].BandwidthKbps)
	}
}

func TestReadExistingAssetFileDefaultsGranularity(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "assets.json")
	if err := os.WriteFile(input, []byte(`{"intra_domain_links":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := readAssetFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.BWGranularity != 1 || loaded.TimeGranularity != 1 {
		t.Fatalf("unexpected default granularity: bw %d time %d",
			loaded.BWGranularity, loaded.TimeGranularity)
	}
}

func TestMergeAssetLinksPreservesUnmatchedExistingLinks(t *testing.T) {
	current := newAssetLinks([]intraDomainLink{{
		FromInterface: 1,
		ToInterface:   2,
		BandwidthKbps: 100,
	}})
	existing := []assetLink{
		{
			Link: intraDomainLink{FromInterface: 1, ToInterface: 2, BandwidthKbps: 100},
			Assets: []linkAsset{{
				BandwidthKbps: 40,
				Start:         time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 5, 11, 0, 0, 0, time.UTC),
			}},
		},
		{
			Link: intraDomainLink{FromInterface: 7, ToInterface: 8, BandwidthKbps: 200},
			Assets: []linkAsset{{
				BandwidthKbps: 90,
				Start:         time.Date(2026, 5, 6, 10, 0, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 6, 11, 0, 0, 0, time.UTC),
			}},
		},
	}

	merged := mergeAssetLinks(current, existing)
	if len(merged) != 2 {
		t.Fatalf("unexpected link count: got %d want 2", len(merged))
	}
	if merged[1].Link.FromInterface != 7 || merged[1].Link.ToInterface != 8 {
		t.Fatalf("unmatched link was not preserved: %+v", merged[1].Link)
	}
	if len(merged[1].Assets) != 1 {
		t.Fatalf("unexpected unmatched asset count: got %d want 1",
			len(merged[1].Assets))
	}
}

func TestPrintAssetLinksIncludesAssets(t *testing.T) {
	var out bytes.Buffer
	printAssetLinks(&out, []assetLink{{
		Link: intraDomainLink{
			FromInterface: 1,
			ToInterface:   2,
			BandwidthKbps: 100,
		},
		Assets: []linkAsset{{
			BandwidthKbps: 40,
			Start:         time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
			End:           time.Date(2026, 5, 5, 11, 0, 0, 0, time.UTC),
		}},
	}}, 5, 60)

	got := out.String()
	for _, want := range []string{
		"Granularity: bw_granularity 5 Kbit/s, time_granularity 60 second(s)",
		"1 <-> 2",
		"40 Kbit/s",
		"2026-05-05T10:00:00Z to 2026-05-05T11:00:00Z",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("listing output missing %q in:\n%s", want, got)
		}
	}
}

func TestPromptAssetsSelectsLinkAndPrintsAfterAdd(t *testing.T) {
	links := []assetLink{
		{
			Link: intraDomainLink{
				FromInterface: 1,
				ToInterface:   2,
				BandwidthKbps: 100,
			},
			Assets: []linkAsset{},
		},
		{
			Link: intraDomainLink{
				FromInterface: 2,
				ToInterface:   3,
				BandwidthKbps: 100,
			},
			Assets: []linkAsset{},
		},
	}
	input := strings.NewReader("b\n10\nt\n60\n2\n30\n2026-05-05 10:00:05\n2026-05-05 11:00:05\n\n")
	var out bytes.Buffer
	bwGranularity := uint64(1)
	timeGranularity := uint64(1)

	if err := promptAssets(bufio.NewReader(input), &out, links,
		&bwGranularity, &timeGranularity); err != nil {
		t.Fatal(err)
	}
	if bwGranularity != 10 || timeGranularity != 60 {
		t.Fatalf("unexpected granularity: bw %d time %d", bwGranularity, timeGranularity)
	}
	if len(links[0].Assets) != 0 {
		t.Fatalf("unexpected assets on first link: %+v", links[0].Assets)
	}
	if len(links[1].Assets) != 1 {
		t.Fatalf("unexpected assets on second link: %+v", links[1].Assets)
	}

	got := out.String()
	if got := strings.Count(got,
		"Granularity: bw_granularity 10 Kbit/s, time_granularity 60 second(s)"); got != 1 {
		t.Fatalf("unexpected granularity line count: got %d want 1 in:\n%s", got, out.String())
	}
	for _, want := range []string{
		"Select link number",
		"Granularity: bw_granularity 10 Kbit/s, time_granularity 60 second(s)",
		"bandwidth granularity: ",
		"time granularity: ",
		"Adding asset for 2 <-> 3.",
		"2 <-> 3",
		"30 Kbit/s, 2026-05-05T10:00:05",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("prompt output missing %q in:\n%s", want, got)
		}
	}
}

func TestValidateAssetGranularity(t *testing.T) {
	asset := linkAsset{
		BandwidthKbps: 30,
		Start:         time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
		End:           time.Date(2026, 5, 5, 10, 5, 0, 0, time.UTC),
	}
	if err := validateAssetGranularity(asset, 10, 60); err != nil {
		t.Fatal(err)
	}
	if err := validateAssetGranularity(asset, 20, 60); err == nil {
		t.Fatal("expected bandwidth granularity error")
	}
	if err := validateAssetGranularity(asset, 10, 120); err == nil {
		t.Fatal("expected time granularity error")
	}
}

func TestRunBandwidthAssetsNonInteractiveReadsInputAssetsWithoutWriting(t *testing.T) {
	tmp := t.TempDir()
	topologyPath := filepath.Join(tmp, "topology.json")
	staticInfoPath := filepath.Join(tmp, "staticInfoConfig.json")
	inputPath := filepath.Join(tmp, "assets.json")
	outputPath := filepath.Join(tmp, "output.json")

	if err := os.WriteFile(topologyPath, []byte(`{
  "isd_as": "1-ff00:0:110",
  "mtu": 1472,
  "dispatched_ports": "31000-32767",
  "attributes": ["core"],
  "border_routers": {
    "br1": {
      "internal_addr": "127.0.0.1:31002",
      "interfaces": {
        "1": {
          "underlay": {
            "public": "127.0.0.4:50000",
            "remote": "127.0.0.5:50000"
          },
          "isd_as": "1-ff00:0:120",
          "link_to": "core",
          "mtu": 1472
        }
      }
    },
    "br2": {
      "internal_addr": "127.0.0.2:31002",
      "interfaces": {
        "2": {
          "underlay": {
            "public": "127.0.0.6:50000",
            "remote": "127.0.0.7:50000"
          },
          "isd_as": "1-ff00:0:130",
          "link_to": "core",
          "mtu": 1472
        }
      }
    }
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staticInfoPath, []byte(`{
  "Bandwidth": {
    "1": {"Inter": 100, "Intra": {"2": 50}},
    "2": {"Inter": 100, "Intra": {"1": 50}}
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, []byte(`{
  "bw_granularity": 5,
  "time_granularity": 60,
  "intra_domain_links": [
    {
      "link": {
        "from_interface": 1,
        "to_interface": 2,
        "bandwidth_kbit": 50
      },
      "assets": [
        {
          "bandwidth_kbit": 10,
          "start": "2026-01-01T00:00:00Z",
          "end": "2026-01-10T00:00:00Z"
        }
      ]
    }
  ]
}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	err := runBandwidthAssets(strings.NewReader(""), &out, bandwidthAssetFlags{
		topologyPath:   topologyPath,
		staticInfo:     staticInfoPath,
		input:          inputPath,
		output:         outputPath,
		nonInteractive: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("non-interactive mode wrote output file, stat err: %v", err)
	}
	got := out.String()
	for _, want := range []string{
		"Granularity: bw_granularity 5 Kbit/s, time_granularity 60 second(s)",
		"1 <-> 2",
		"10 Kbit/s",
		"2026-01-01T00:00:00Z to 2026-01-10T00:00:00Z",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("non-interactive output missing %q in:\n%s", want, got)
		}
	}
}

func TestRunBandwidthAssetsWritesGranularity(t *testing.T) {
	tmp := t.TempDir()
	topologyPath := filepath.Join(tmp, "topology.json")
	staticInfoPath := filepath.Join(tmp, "staticInfoConfig.json")
	inputPath := filepath.Join(tmp, "assets.json")
	outputPath := filepath.Join(tmp, "output.json")
	writeMinimalAssetTestFiles(t, topologyPath, staticInfoPath, inputPath)

	var out bytes.Buffer
	err := runBandwidthAssets(strings.NewReader("\n"), &out, bandwidthAssetFlags{
		topologyPath: topologyPath,
		staticInfo:   staticInfoPath,
		input:        inputPath,
		output:       outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "from_router") || strings.Contains(string(raw), "to_router") {
		t.Fatalf("written output contains router fields:\n%s", raw)
	}
	var written assetFile
	if err := json.Unmarshal(raw, &written); err != nil {
		t.Fatal(err)
	}
	if written.BWGranularity != 5 || written.TimeGranularity != 60 {
		t.Fatalf("unexpected written granularity: bw %d time %d",
			written.BWGranularity, written.TimeGranularity)
	}
}

func TestRunBandwidthAssetsWritesDefaultGranularity(t *testing.T) {
	tmp := t.TempDir()
	topologyPath := filepath.Join(tmp, "topology.json")
	staticInfoPath := filepath.Join(tmp, "staticInfoConfig.json")
	inputPath := filepath.Join(tmp, "assets.json")
	outputPath := filepath.Join(tmp, "output.json")
	writeMinimalAssetTestFiles(t, topologyPath, staticInfoPath, inputPath)

	var out bytes.Buffer
	err := runBandwidthAssets(strings.NewReader("\n"), &out, bandwidthAssetFlags{
		topologyPath: topologyPath,
		staticInfo:   staticInfoPath,
		output:       outputPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var written assetFile
	if err := json.Unmarshal(raw, &written); err != nil {
		t.Fatal(err)
	}
	if written.BWGranularity != 1 || written.TimeGranularity != 1 {
		t.Fatalf("unexpected written granularity: bw %d time %d",
			written.BWGranularity, written.TimeGranularity)
	}
}

func writeMinimalAssetTestFiles(t *testing.T, topologyPath, staticInfoPath, inputPath string) {
	t.Helper()
	if err := os.WriteFile(topologyPath, []byte(`{
  "isd_as": "1-ff00:0:110",
  "mtu": 1472,
  "dispatched_ports": "31000-32767",
  "attributes": ["core"],
  "border_routers": {
    "br1": {
      "internal_addr": "127.0.0.1:31002",
      "interfaces": {
        "1": {
          "underlay": {
            "public": "127.0.0.4:50000",
            "remote": "127.0.0.5:50000"
          },
          "isd_as": "1-ff00:0:120",
          "link_to": "core",
          "mtu": 1472
        }
      }
    },
    "br2": {
      "internal_addr": "127.0.0.2:31002",
      "interfaces": {
        "2": {
          "underlay": {
            "public": "127.0.0.6:50000",
            "remote": "127.0.0.7:50000"
          },
          "isd_as": "1-ff00:0:130",
          "link_to": "core",
          "mtu": 1472
        }
      }
    }
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staticInfoPath, []byte(`{
  "Bandwidth": {
    "1": {"Inter": 100, "Intra": {"2": 50}},
    "2": {"Inter": 100, "Intra": {"1": 50}}
  }
}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inputPath, []byte(`{
  "bw_granularity": 5,
  "time_granularity": 60,
  "intra_domain_links": [
    {
      "link": {
        "from_interface": 1,
        "to_interface": 2,
        "bandwidth_kbit": 50
      },
      "assets": [
        {
          "bandwidth_kbit": 10,
          "start": "2026-01-01T00:00:00Z",
          "end": "2026-01-10T00:00:00Z"
        }
      ]
    }
  ]
}`), 0o644); err != nil {
		t.Fatal(err)
	}
}

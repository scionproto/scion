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

func TestParseReservationTime(t *testing.T) {
	rfc3339, err := parseReservationTime("2026-05-05T12:30:00Z", startOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if !rfc3339.Equal(time.Date(2026, 5, 5, 12, 30, 0, 0, time.UTC)) {
		t.Fatalf("unexpected RFC3339 time: %s", rfc3339)
	}

	local, err := parseReservationTime("2026-05-05 12:30", startOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if local.Location() != time.Local {
		t.Fatalf("unexpected location: got %s want %s", local.Location(), time.Local)
	}

	withSeconds, err := parseReservationTime("2026-05-05 12:30:45", startOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if withSeconds.Second() != 45 {
		t.Fatalf("unexpected seconds: got %d want 45", withSeconds.Second())
	}

	startDefault, err := parseReservationTime("2026-05-05", startOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if startDefault.Hour() != 0 || startDefault.Minute() != 0 || startDefault.Second() != 0 {
		t.Fatalf("unexpected start default: %s", startDefault)
	}

	endDefault, err := parseReservationTime("2026-05-05", endOfDay)
	if err != nil {
		t.Fatal(err)
	}
	if endDefault.Hour() != 23 || endDefault.Minute() != 59 || endDefault.Second() != 39 {
		t.Fatalf("unexpected end default: %s", endDefault)
	}

	if _, err := parseReservationTime("not a time", startOfDay); err == nil {
		t.Fatal("expected invalid time error")
	}
}

func TestValidateLinkReservationsRejectsOverbooking(t *testing.T) {
	link := reservedLink{
		Link: intraDomainLink{
			FromInterface: 1,
			ToInterface:   2,
			BandwidthKbps: 100,
		},
		Reservations: []linkReservation{
			{
				BandwidthKbps: 60,
				Start:         time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 5, 11, 0, 0, 0, time.UTC),
			},
			{
				BandwidthKbps: 50,
				Start:         time.Date(2026, 5, 5, 10, 30, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 5, 11, 30, 0, 0, time.UTC),
			},
		},
	}

	if err := validateLinkReservations(link); err == nil {
		t.Fatal("expected overbooking error")
	}
}

func TestValidateLinkReservationsAllowsAdjacentReservations(t *testing.T) {
	link := reservedLink{
		Link: intraDomainLink{
			FromInterface: 1,
			ToInterface:   2,
			BandwidthKbps: 100,
		},
		Reservations: []linkReservation{
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

	if err := validateLinkReservations(link); err != nil {
		t.Fatal(err)
	}
}

func TestReadExistingReservationFileAndMerge(t *testing.T) {
	tmp := t.TempDir()
	input := filepath.Join(tmp, "reservations.json")
	existing := reservationFile{
		IntraDomainLinks: []reservedLink{
			{
				Link: intraDomainLink{FromInterface: 2, ToInterface: 1},
				Reservations: []linkReservation{{
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

	loaded, err := readReservationFile(input)
	if err != nil {
		t.Fatal(err)
	}
	current := newReservationLinks([]intraDomainLink{{
		FromInterface: 1,
		ToInterface:   2,
		BandwidthKbps: 100,
	}})
	merged := mergeReservationLinks(current, loaded.IntraDomainLinks)

	if len(merged[0].Reservations) != 1 {
		t.Fatalf("unexpected reservation count: got %d want 1", len(merged[0].Reservations))
	}
	if merged[0].Reservations[0].BandwidthKbps != 40 {
		t.Fatalf("unexpected reservation bandwidth: got %d want 40",
			merged[0].Reservations[0].BandwidthKbps)
	}
}

func TestMergeReservationLinksPreservesUnmatchedExistingLinks(t *testing.T) {
	current := newReservationLinks([]intraDomainLink{{
		FromInterface: 1,
		ToInterface:   2,
		BandwidthKbps: 100,
	}})
	existing := []reservedLink{
		{
			Link: intraDomainLink{FromInterface: 1, ToInterface: 2, BandwidthKbps: 100},
			Reservations: []linkReservation{{
				BandwidthKbps: 40,
				Start:         time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 5, 11, 0, 0, 0, time.UTC),
			}},
		},
		{
			Link: intraDomainLink{FromInterface: 7, ToInterface: 8, BandwidthKbps: 200},
			Reservations: []linkReservation{{
				BandwidthKbps: 90,
				Start:         time.Date(2026, 5, 6, 10, 0, 0, 0, time.UTC),
				End:           time.Date(2026, 5, 6, 11, 0, 0, 0, time.UTC),
			}},
		},
	}

	merged := mergeReservationLinks(current, existing)
	if len(merged) != 2 {
		t.Fatalf("unexpected link count: got %d want 2", len(merged))
	}
	if merged[1].Link.FromInterface != 7 || merged[1].Link.ToInterface != 8 {
		t.Fatalf("unmatched link was not preserved: %+v", merged[1].Link)
	}
	if len(merged[1].Reservations) != 1 {
		t.Fatalf("unexpected unmatched reservation count: got %d want 1",
			len(merged[1].Reservations))
	}
}

func TestPrintReservationLinksIncludesReservations(t *testing.T) {
	var out bytes.Buffer
	printReservationLinks(&out, []reservedLink{{
		Link: intraDomainLink{
			FromInterface: 1,
			ToInterface:   2,
			FromRouter:    "br1",
			ToRouter:      "br2",
			BandwidthKbps: 100,
		},
		Reservations: []linkReservation{{
			BandwidthKbps: 40,
			Start:         time.Date(2026, 5, 5, 10, 0, 0, 0, time.UTC),
			End:           time.Date(2026, 5, 5, 11, 0, 0, 0, time.UTC),
		}},
	}})

	got := out.String()
	for _, want := range []string{
		"if1 (br1) <-> if2 (br2)",
		"40 Kbit/s",
		"2026-05-05T10:00:00Z to 2026-05-05T11:00:00Z",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("listing output missing %q in:\n%s", want, got)
		}
	}
}

func TestPromptReservationsSelectsLinkAndPrintsAfterAdd(t *testing.T) {
	links := []reservedLink{
		{
			Link: intraDomainLink{
				FromInterface: 1,
				ToInterface:   2,
				FromRouter:    "br1",
				ToRouter:      "br2",
				BandwidthKbps: 100,
			},
			Reservations: []linkReservation{},
		},
		{
			Link: intraDomainLink{
				FromInterface: 2,
				ToInterface:   3,
				FromRouter:    "br2",
				ToRouter:      "br3",
				BandwidthKbps: 100,
			},
			Reservations: []linkReservation{},
		},
	}
	input := strings.NewReader("2\n30\n2026-05-05 10:00:05\n2026-05-05 11:00:06\n\n")
	var out bytes.Buffer

	if err := promptReservations(bufio.NewReader(input), &out, links); err != nil {
		t.Fatal(err)
	}
	if len(links[0].Reservations) != 0 {
		t.Fatalf("unexpected reservations on first link: %+v", links[0].Reservations)
	}
	if len(links[1].Reservations) != 1 {
		t.Fatalf("unexpected reservations on second link: %+v", links[1].Reservations)
	}

	got := out.String()
	for _, want := range []string{
		"Select link number",
		"Adding reservation for if2 <-> if3.",
		"if2 (br2) <-> if3 (br3)",
		"30 Kbit/s, 2026-05-05T10:00:05",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("prompt output missing %q in:\n%s", want, got)
		}
	}
}

func TestRunBandwidthReservationsNonInteractiveReadsInputReservationsWithoutWriting(t *testing.T) {
	tmp := t.TempDir()
	topologyPath := filepath.Join(tmp, "topology.json")
	staticInfoPath := filepath.Join(tmp, "staticInfoConfig.json")
	inputPath := filepath.Join(tmp, "reservations.json")
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
  "intra_domain_links": [
    {
      "link": {
        "from_interface": 1,
        "to_interface": 2,
        "from_router": "br1",
        "to_router": "br2",
        "bandwidth_kbit": 50
      },
      "reservations": [
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
	err := runBandwidthReservations(strings.NewReader(""), &out, bandwidthReservationFlags{
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
		"if1 (br1) <-> if2 (br2)",
		"10 Kbit/s",
		"2026-01-01T00:00:00Z to 2026-01-10T00:00:00Z",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("non-interactive output missing %q in:\n%s", want, got)
		}
	}
}

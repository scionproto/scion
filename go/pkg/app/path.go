// Copyright 2020 Anapaya Systems
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

package app

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"

	"github.com/scionproto/scion/go/lib/snet"
)

// SortPaths sorts paths according to hops and interfaces.
func SortPaths(paths []snet.Path) {
	sort.Slice(paths, func(a, b int) bool {
		intfA, intfB := paths[a].Metadata().Interfaces, paths[b].Metadata().Interfaces
		// Sort according to path length.
		if len(intfA) != len(intfB) {
			return len(intfA) < len(intfB)
		}
		for i := range intfA {
			if iaA, iaB := intfA[i].IA.IAInt(), intfA[i].IA.IAInt(); iaA != iaB {
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
	return fmt.Sprintf("%s: %s", cs.Keys.Sprintf(k), cs.Values.Sprintf(v))
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

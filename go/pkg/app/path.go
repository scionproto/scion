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
		intfA, intfB := paths[a].Interfaces(), paths[b].Interfaces()
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
		expA, expB := paths[a].Metadata().Expiry(), paths[b].Metadata().Expiry()
		if !expA.Equal(expB) {
			return expA.Before(expB)
		}
		return true
	})
}

// ColorOption allows customizing the path coloring.
type ColorOption func(*colorOptions)

// WithDisableColor sets wether coloring is disabled.
func WithDisableColor(disable bool) ColorOption {
	return func(opts *colorOptions) {
		opts.disable = disable
	}
}

type colorOptions struct {
	disable bool
	keys    *color.Color
	values  *color.Color
	link    *color.Color
	intf    *color.Color
}

func applyColorOptions(opts ...ColorOption) colorOptions {
	o := colorOptions{
		keys:   color.New(color.FgHiCyan),
		values: color.New(),
		link:   color.New(color.FgHiMagenta),
		intf:   color.New(color.FgYellow),
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// ColorPath returns a colored path description.
func ColorPath(path snet.Path, opts ...ColorOption) string {
	o := applyColorOptions(opts...)
	if o.disable {
		return fmt.Sprint(path)
	}
	hops := coloredHops(path, o)
	entries := []string{
		fmt.Sprintf("%s: [%s]", o.keys.Sprint("Hops"), strings.Join(hops, o.link.Sprint(">"))),
		fmt.Sprintf("%s: %s", o.keys.Sprint("MTU"), o.values.Sprint(path.Metadata().MTU())),
		fmt.Sprintf("%s: %s", o.keys.Sprint("NextHop"), o.values.Sprint(path.UnderlayNextHop())),
	}
	return strings.Join(entries, " ")
}

func coloredHops(path snet.Path, opts colorOptions) []string {
	if path == nil {
		return nil
	}
	intfs := path.Interfaces()
	if len(intfs) == 0 {
		return nil
	}
	var hops []string
	intf := intfs[0]
	hops = append(hops, opts.values.Sprintf("%s %s",
		opts.values.Sprint(intf.IA),
		opts.intf.Sprint(intf.ID),
	))
	for i := 1; i < len(intfs)-1; i += 2 {
		inIntf := intfs[i]
		outIntf := intfs[i+1]
		hops = append(hops, opts.values.Sprintf("%s %s %s",
			opts.intf.Sprint(inIntf.ID),
			opts.values.Sprint(inIntf.IA),
			opts.intf.Sprint(outIntf.ID),
		))
	}
	intf = intfs[len(intfs)-1]
	hops = append(hops, opts.values.Sprintf("%s %s",
		opts.intf.Sprint(intf.ID),
		opts.values.Sprint(intf.IA),
	))
	return hops
}

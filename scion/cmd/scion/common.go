// Copyright 2022 Anapaya Systems
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
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/segment/iface"
	"github.com/scionproto/scion/pkg/snet"
)

// Path defines the base model for the `ping` and `traceroute` result path
type Path struct {
	// Hex-string representing the paths fingerprint.
	Fingerprint string `json:"fingerprint" yaml:"fingerprint"`
	Hops        []Hop  `json:"hops" yaml:"hops"`
	Sequence    string `json:"sequence" yaml:"sequence"`

	LocalIP net.IP `json:"local_ip,omitempty" yaml:"local_ip,omitempty"`

	// The internal UDP/IP underlay address of the SCION router that forwards traffic for this path.
	NextHop string `json:"next_hop" yaml:"next_hop"`
}

// Hop represents an hop on the path.
type Hop struct {
	ID iface.ID `json:"interface" yaml:"interface"`
	IA addr.IA  `json:"isd_as" yaml:"isd_as"`
}

// getHops constructs a list of snet path interfaces from an snet path
func getHops(path snet.Path) []Hop {
	ifaces := path.Metadata().Interfaces
	var hops []Hop
	if len(ifaces) == 0 {
		return hops
	}
	for i := range ifaces {
		intf := ifaces[i]
		hops = append(hops, Hop{IA: intf.IA, ID: intf.ID})
	}
	return hops
}

// getPrintf returns a printf function for the "human" formatting flag and an empty one for machine
// readable format flags
func getPrintf(output string, writer io.Writer) (func(format string, ctx ...interface{}), error) {
	switch output {
	case "human":
		return func(format string, ctx ...interface{}) {
			fmt.Fprintf(writer, format, ctx...)
		}, nil
	case "yaml", "json":
		return func(format string, ctx ...interface{}) {}, nil
	default:
		return nil, serrors.New("format not supported", "format", output)
	}
}

type durationMillis time.Duration

func (d durationMillis) String() string {
	return fmt.Sprintf("%.3fms", d.Millis())
}

func (d durationMillis) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.MillisRounded())
}

func (d durationMillis) MarshalYAML() (interface{}, error) {
	return d.MillisRounded(), nil
}

// millis returns the duration as a floating point number of milliseconds
func (d durationMillis) Millis() float64 {
	return float64(d) / 1e6
}

// millisRounded returns the duration as a floating point number of
// milliseconds, rounded to microseconds (3 digits precision).
func (d durationMillis) MillisRounded() float64 {
	return math.Round(float64(d)/1000) / 1000
}

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

package topology

import "strings"

// ServiceType describes the type of servce.
type ServiceType int

// Service types
const (
	Unknown = iota
	Router
	Control
	Discovery
	Gateway
	HiddenSegmentLookup
	HiddenSegmentRegistration
)

func (t ServiceType) String() string {
	switch t {
	case Router:
		return "router"
	case Control:
		return "control"
	case Discovery:
		return "discovery"
	case Gateway:
		return "gateway"
	case HiddenSegmentLookup:
		return "hiddensegmentlookup"
	case HiddenSegmentRegistration:
		return "hiddensegmentregistration"
	default:
		return "unknown"
	}
}

// ServiceTypeFromString parses the service type.
func ServiceTypeFromString(s string) ServiceType {
	switch strings.ToLower(s) {
	case "router":
		return Router
	case "control":
		return Control
	case "discovery":
		return Discovery
	case "gateway":
		return Gateway
	case "hiddensegmentlookup":
		return HiddenSegmentLookup
	case "hiddensegmentregistration":
		return HiddenSegmentRegistration
	default:
		return Unknown
	}
}

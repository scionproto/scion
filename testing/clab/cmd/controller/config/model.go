// Copyright 2026 Anapaya Systems
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

// Package config defines the generalized SCION configuration model.
//
// A [Config] is the generalized configuration for a single host — the
// equivalent of one appliance in the Anapaya configuration model. It describes
// only the elements that host runs, never the rest of the AS. Because it is
// purely local and self-contained, a service process can render its own config
// into service-specific files (see the prism package). The model is
// format-agnostic: it serializes identically to YAML and JSON (see encode.go).
package config

import (
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
)

// Config is the generalized configuration for one host.
type Config struct {
	SCION      SCION      `json:"scion" yaml:"scion"`
	Interfaces Interfaces `json:"interfaces" yaml:"interfaces"`
}

// SCION is the SCION control/data-plane section.
type SCION struct {
	// ASes are the ASes this host participates in (usually exactly one).
	ASes []AS `json:"ases" yaml:"ases"`
}

// AS describes one AS's local elements. The optional Router/Control/Daemon/Gateway
// fields are set exactly for the elements running on this host; their presence
// is the host's role.
type AS struct {
	ISDAS     addr.IA    `json:"isd_as" yaml:"isd_as"`
	Core      bool       `json:"core" yaml:"core"`
	MTU       int        `json:"mtu" yaml:"mtu"`
	Router    *Router    `json:"router,omitempty" yaml:"router,omitempty"`
	Control   *Control   `json:"control,omitempty" yaml:"control,omitempty"`
	Daemon    *Daemon    `json:"daemon,omitempty" yaml:"daemon,omitempty"`
	Gateway   *Gateway   `json:"gateway,omitempty" yaml:"gateway,omitempty"`
	Neighbors []Neighbor `json:"neighbors,omitempty" yaml:"neighbors,omitempty"`
}

// Router is the data-plane (border router) element on this host.
type Router struct {
	ID                string         `json:"id" yaml:"id"`
	InternalInterface netip.AddrPort `json:"internal_interface" yaml:"internal_interface"`
	APIAddr           netip.AddrPort `json:"api_addr" yaml:"api_addr"`
	SCIONMTU          int            `json:"scion_mtu" yaml:"scion_mtu"`
}

// Control is the control service element on this host.
type Control struct {
	ID      string         `json:"id" yaml:"id"`
	Address netip.AddrPort `json:"address" yaml:"address"`
	APIAddr netip.AddrPort `json:"api_addr" yaml:"api_addr"`
	// Issuing indicates the control service runs the CA (issues certificates).
	Issuing bool `json:"issuing" yaml:"issuing"`
}

// Daemon is the SCION daemon (sciond) element on this host.
type Daemon struct {
	ID      string         `json:"id" yaml:"id"`
	Address netip.AddrPort `json:"address" yaml:"address"`
	APIAddr netip.AddrPort `json:"api_addr" yaml:"api_addr"`
}

// Gateway is the SCION IP gateway (SIG) element on this host. It tunnels IP
// traffic for the remote prefixes over SCION to the gateways of the remote ASes.
type Gateway struct {
	ID string `json:"id" yaml:"id"`
	// CtrlAddr, DataAddr and ProbeAddr are the SCION/UDP addresses of the
	// gateway's prefix discovery, data plane and path probing endpoints.
	CtrlAddr  netip.AddrPort `json:"ctrl_addr" yaml:"ctrl_addr"`
	DataAddr  netip.AddrPort `json:"data_addr" yaml:"data_addr"`
	ProbeAddr netip.AddrPort `json:"probe_addr" yaml:"probe_addr"`
	APIAddr   netip.AddrPort `json:"api_addr" yaml:"api_addr"`
	// Daemon is the API address of the SCION daemon the gateway uses.
	Daemon netip.AddrPort `json:"daemon" yaml:"daemon"`
	// TunnelSrcV4 is the source address of IPv4 traffic that the host itself
	// sends through the tunnel. It must be assigned to a local interface.
	//
	// The yaml tag has no omitempty: go-yaml considers a netip.Addr empty
	// even if it is set, and does not support omitzero.
	TunnelSrcV4 netip.Addr `json:"tunnel_src_ipv4,omitzero" yaml:"tunnel_src_ipv4"`
	// Remotes are the remote ASes and the IP prefixes routed to them.
	Remotes []GatewayRemote `json:"remotes,omitempty" yaml:"remotes,omitempty"`
}

// GatewayRemote is a remote AS and the IP prefixes that the gateway routes to
// that AS's gateways.
type GatewayRemote struct {
	ISDAS    addr.IA        `json:"isd_as" yaml:"isd_as"`
	Prefixes []netip.Prefix `json:"prefixes" yaml:"prefixes"`
}

// Neighbor is a neighboring AS reachable over one or more interfaces on this
// host's border router.
type Neighbor struct {
	ISDAS        addr.IA     `json:"neighbor_isd_as" yaml:"neighbor_isd_as"`
	Relationship LinkType    `json:"relationship" yaml:"relationship"`
	Interfaces   []Interface `json:"interfaces" yaml:"interfaces"`
}

// Interface is one external SCION interface.
type Interface struct {
	ID       uint64         `json:"interface_id" yaml:"interface_id"`
	Underlay string         `json:"underlay" yaml:"underlay"`
	Address  netip.AddrPort `json:"address" yaml:"address"`
	Remote   Remote         `json:"remote" yaml:"remote"`
	MTU      int            `json:"scion_mtu" yaml:"scion_mtu"`
}

// Remote is the far side of an external interface.
type Remote struct {
	Address netip.AddrPort `json:"address" yaml:"address"`
	ID      uint64         `json:"interface_id" yaml:"interface_id"`
}

// LinkType is the relationship of a neighbor relative to this AS.
type LinkType string

const (
	Core   LinkType = "CORE"
	Parent LinkType = "PARENT"
	Child  LinkType = "CHILD"
	Peer   LinkType = "PEER"
)

// Interfaces is the host network-interface section. It captures the underlay
// binding the SCION addresses sit on, mirroring the Anapaya interfaces model.
type Interfaces struct {
	Ethernets []Ethernet `json:"ethernets,omitempty" yaml:"ethernets,omitempty"`
	Loopbacks []Loopback `json:"loopbacks,omitempty" yaml:"loopbacks,omitempty"`
}

// Ethernet is a physical/virtual network interface with CIDR addresses.
type Ethernet struct {
	Name      string   `json:"name" yaml:"name"`
	Addresses []string `json:"addresses" yaml:"addresses"`
	MTU       int      `json:"mtu,omitempty" yaml:"mtu,omitempty"`
}

// Loopback is a logical loopback interface.
type Loopback struct {
	Name      string   `json:"name" yaml:"name"`
	Addresses []string `json:"addresses" yaml:"addresses"`
}

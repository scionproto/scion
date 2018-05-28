// Copyright 2016 ETH Zurich
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

/*
The topology package wraps two versions of the topology. The first is RawTopo
(in raw.go), which closely matches the JSON format. It is mainly used for
loading the topology from disk. The second data structure is Topo. It is used
by Go code directly and thus has a different structure and stricter types.

Since the RawTopo format is pretty self-explanatory, we will focus on the Topo
structure here.

The basic layout is as follows:

type Topo struct {
    Timestamp      int64
    TimestampHuman string
    ISD_AS         addr.IA
    Overlay        overlay.Type
    MTU            int
    Core           bool

    BR             map[string]BRInfo
    BRNames        []string
    // This maps Interface IDs to internal addresses. Clients use this to
    // figure out which internal BR address they have to send their traffic to
    // if they want to use a given (external) interface.
    IFInfoMap map[common.IFIDType]IFInfo

    BS      map[string]TopoAddr
    BSNames []string
    CS      map[string]TopoAddr
    CSNames []string
    PS      map[string]TopoAddr
    PSNames []string
    SB      map[string]TopoAddr
    SBNames []string
    RS      map[string]TopoAddr
    RSNames []string
    DS      map[string]TopoAddr
    DSNames []string

    ZK map[int]TopoAddr
}

The first section contains metadata about the topology. All of these fields
should be self-explanatory.

The second section concerns the Border routers. BRNames is just a sorted slice
of the names of the BRs in this topolgy. Its contents is exactly the same as
the keys in the BR map.

The BR map points from border router names to BRInfo structs, which in turn
are lists of IFID type slices. This mapping thus defines which IFIDs belong to
a particular border router. The IFInfoMap points from interface IDs to IFInfo
structs:

type IFInfo struct {
    BRName          string
    InternalAddr    *TopoAddr
    Overlay         overlay.Type
    Local           *TopoAddr
    Remote          *AddrInfo
    RemoteIFID      common.IFIDType
    Bandwidth       int
    ISD_AS          addr.IA
    LinkType        LinkType
    MTU             int
}

This struct describes a border router link to another AS, including the
internal address applications should send traffic for the link to
(InternalAddr) and inoformation about the link itself and the remote side of
it.

The third section in Topo concerns the SCION-specific services in the topology.
The structure is identical between the various elements. For each service,
there is again a sorted slice of names of the servers that provide the service.
Additionally, there is a map from those names to TopoAddr structs:

type TopoAddr struct {
    IPv4    *topoAddrInt
    IPv6    *topoAddrInt
    Overlay overlay.Type
}

This structure wraps the possible addresses of a SCION service and describes
the overlay to be used for contacting said service.

The two sub-structures for IPv4 and IPv6 only differ in the type of addresses
they can contain and look like this:

type topoAddrInt struct {
    pubIP       net.IP
    pubL4Port   int
    bindIP      net.IP
    bindL4Port  int
    OverlayPort int
}

Since Go can handle both v4 and v6 addresses in net.IP, no indirection is
needed.

On top of these two structures, there is also AddrInfo:

type AddrInfo struct {
    Overlay     overlay.Type
    IP          net.IP
    L4Port      int
    OverlayPort int
}

This struct is used to point to a specific endpoint, i.e. it does not
distinguish bind and public ports and can only hold either an IPv4 or an IPv6
address.
*/
package topology

//vim: tw=78 fo+=t

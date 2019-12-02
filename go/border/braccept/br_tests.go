// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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

func br_multi() int {
	var failures int

	failures += br_peer()
	failures += br_child()
	failures += br_parent()

	failures += child_to_parent()
	failures += parent_to_child()
	failures += shortcut_child_to_peer()
	failures += shortcut_peer_to_child()
	failures += shortcut_child_to_child()

	failures += revocation_parent_to_child()

	failures += scmpBadVersion()
	failures += scmpBadDstType()
	failures += scmpBadSrcType()
	failures += scmpBadPktLenShort()
	failures += scmpBadPktLenLong()
	failures += scmpBadHdrLenShort()
	failures += scmpBadHdrLenLong()
	failures += scmpBadInfoFieldOffsetLow()
	failures += scmpBadInfoFieldOffsetHigh()
	failures += scmpBadHopFieldOffsetLow()
	failures += scmpBadHopFieldOffsetHigh()
	failures += scmpPathRequired()
	failures += scmpBadMac()
	failures += scmpExpiredHopField()
	failures += scmpBadInterface()
	failures += scmpNonRoutingHopField()
	failures += scmpTooManyHopByHop()
	failures += scmpBadExtensionOrder()
	failures += scmpBadHopByHop()

	return failures
}

func br_peer() int {
	var failures int

	failures += shortcut_peer_to_internal_host()
	failures += shortcut_internal_host_to_peer()
	failures += shortcut_peer_to_internal_child()
	failures += shortcut_internal_child_to_peer()

	failures += revocation_owned_peer()

	failures += scmpBadVersion()
	failures += scmpBadDstType()
	failures += scmpBadSrcType()
	failures += scmpBadPktLenShort()
	failures += scmpBadPktLenLong()
	failures += scmpBadHdrLenShort()
	failures += scmpBadHdrLenLong()
	failures += scmpBadInfoFieldOffsetLow()
	failures += scmpBadInfoFieldOffsetHigh()
	failures += scmpBadHopFieldOffsetLow()
	failures += scmpBadHopFieldOffsetHigh()
	failures += scmpPathRequired()
	failures += scmpBadMac()
	failures += scmpExpiredHopField()
	failures += scmpBadInterface()
	failures += scmpNonRoutingHopField()
	failures += scmpTooManyHopByHop()
	failures += scmpBadExtensionOrder()
	failures += scmpBadHopByHop()

	return failures
}

func br_child() int {
	var failures int

	failures += child_to_internal_host()
	failures += internal_host_to_child()

	failures += child_to_internal_parent()
	failures += internal_parent_to_child()

	failures += shortcut_child_to_internal_peer()
	failures += shortcut_internal_peer_to_child()
	failures += shortcut_child_to_internal_child()
	failures += shortcut_internal_child_to_child()

	failures += revocation_child_to_internal_host()

	failures += scmpBadVersion()
	failures += scmpBadDstType()
	failures += scmpBadSrcType()
	failures += scmpBadPktLenShort()
	failures += scmpBadPktLenLong()
	failures += scmpBadHdrLenShort()
	failures += scmpBadHdrLenLong()
	failures += scmpBadInfoFieldOffsetLow()
	failures += scmpBadInfoFieldOffsetHigh()
	failures += scmpBadHopFieldOffsetLow()
	failures += scmpBadHopFieldOffsetHigh()
	failures += scmpPathRequired()
	failures += scmpBadMac()
	failures += scmpExpiredHopField()
	failures += scmpBadInterface()
	failures += scmpNonRoutingHopField()
	failures += scmpTooManyHopByHop()
	failures += scmpBadExtensionOrder()
	failures += scmpBadHopByHop()

	return failures
}

func br_parent() int {
	var failures int

	failures += parent_to_internal_host()
	failures += internal_host_to_parent()
	failures += parent_to_internal_child()
	failures += internal_child_to_parent()

	// XXX(sgmonroy) the following tests are only run for this specific BR configuration
	// with a single parent interface. In the current implementation, the behavior would be
	// the same regardless of the link type that the packet was recevied on.
	failures += svc_anycast_parent_to_internal_host()
	failures += svc_multicast_parent_to_internal_host()
	failures += svc_multicast_same_host_parent_to_internal_host()

	failures += revocation_owned_parent()
	failures += revocation_not_owned_child_link()

	failures += ohp_parent_to_internal_bs()
	failures += ohp_udp_parent_to_internal_bs()
	failures += ohp_udp_internal_bs_to_parent()
	failures += ohp_internal_bs_to_parent()

	failures += parent_scmp_routing_bad_host()

	failures += scmpBadVersion()
	failures += scmpBadDstType()
	failures += scmpBadSrcType()
	failures += scmpBadPktLenShort()
	failures += scmpBadPktLenLong()
	failures += scmpBadHdrLenShort()
	failures += scmpBadHdrLenLong()
	failures += scmpBadInfoFieldOffsetLow()
	failures += scmpBadInfoFieldOffsetHigh()
	failures += scmpBadHopFieldOffsetLow()
	failures += scmpBadHopFieldOffsetHigh()
	failures += scmpPathRequired()
	failures += scmpBadMac()
	failures += scmpExpiredHopField()
	failures += scmpBadInterface()
	failures += scmpNonRoutingHopField()
	failures += scmpTooManyHopByHop()
	failures += scmpBadExtensionOrder()
	failures += scmpBadHopByHop()

	return failures
}

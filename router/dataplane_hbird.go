// Copyright 2025 ETH Zurich
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

package router

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/gopacket/gopacket"

	"github.com/scionproto/scion/pkg/log"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/private/util"
	"github.com/scionproto/scion/pkg/slayers"
	"github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/spao"
	"github.com/scionproto/scion/router/tokenbucket"
)

// SetHbirdKey sets the key for the PRF function used to compute the Hummingbird Auth Key.
func (d *dataPlane) SetHbirdKey(key []byte) error {
	d.mtx.Lock()
	defer d.mtx.Unlock()
	if d.isRunning() {
		return errModifyExisting
	}
	if len(key) == 0 {
		return errEmptyValue
	}
	if d.prfFactory != nil {
		return errAlreadySet
	}
	// First check for cipher creation errors
	if _, err := aes.NewCipher(key); err != nil {
		return err
	}
	d.prfFactory = func() cipher.Block {
		prf, _ := aes.NewCipher(key)
		return prf
	}
	return nil
}

func (p *scionPacketProcessor) parseHbirdPath() disposition {
	var err error
	p.flyoverField, err = p.hbirdPath.GetCurrentHopField()
	if err != nil {
		return errorDiscard(err, errMalformedPath)
	}
	p.hopField = p.flyoverField.HopField
	p.infoField, err = p.hbirdPath.GetCurrentInfoField()
	if err != nil {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return errorDiscard("error", err)
	}
	if p.flyoverField.Flyover {
		p.hasPriority = true
	}

	return pForward
}

func determinePeerHbird(pathMeta hummingbird.MetaHdr, inf path.InfoField) (bool, error) {
	if !inf.Peer {
		return false, nil
	}

	if pathMeta.SegLen[0] == 0 {
		return false, errPeeringEmptySeg0
	}
	if pathMeta.SegLen[1] == 0 {
		return false, errPeeringEmptySeg1

	}
	if pathMeta.SegLen[2] != 0 {
		return false, errPeeringNonemptySeg2
	}

	// The peer hop fields are the last hop field on the first path
	// segment (at SegLen[0] - 1) and the first hop field of the second
	// path segment (at SegLen[0]). The below check applies only
	// because we already know this is a well-formed peering path.
	currHF := pathMeta.CurrHF
	segLen := pathMeta.SegLen[0]
	peer := currHF == segLen-hummingbird.HopLines || currHF == segLen-hummingbird.FlyoverLines ||
		currHF == segLen
	return peer, nil
}

func (p *scionPacketProcessor) determinePeerHbird() disposition {
	peer, err := determinePeerHbird(p.hbirdPath.PathMeta, p.infoField)
	p.peering = peer
	if err != nil {
		return errorDiscard("error", err)
	}
	return pForward
}

func (p *scionPacketProcessor) validateHopExpiryHbird() disposition {
	expiration := util.SecsToTime(p.infoField.Timestamp).
		Add(path.ExpTimeToDuration(p.hopField.ExpTime))
	expired := expiration.Before(time.Now())
	if !expired {
		return pForward
	}
	log.Debug("SCMP response", "cause", errExpiredHop,
		"cons_dir", p.infoField.ConsDir, "if_id", p.ingressFromLink,
		"curr_inf", p.hbirdPath.PathMeta.CurrINF, "curr_hf", p.hbirdPath.PathMeta.CurrHF)
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodePathExpired,
		pointer: p.currentHopPointer(),
	}
	return pSlowPath
}

func (p *scionPacketProcessor) validateReservationExpiry() disposition {
	startTime := util.SecsToTime(p.hbirdPath.PathMeta.BaseTS - uint32(p.flyoverField.ResStartTime))
	endTime := startTime.Add(time.Duration(p.flyoverField.Duration) * time.Second)
	now := time.Now()
	if startTime.Before(now) && now.Before(endTime) {
		return pForward
	}
	log.Debug("SCMP: Reservation is not valid at current time", "reservation start", startTime,
		"reservation end", endTime, "now", now)
	p.pkt.slowPathRequest = slowPathRequest{
		spType:  slowPathType(slayers.SCMPTypeParameterProblem),
		code:    slayers.SCMPCodeReservationExpired,
		pointer: p.currentHopPointer(),
	}
	return pSlowPath
}

func (p *scionPacketProcessor) currentHbirdInfoPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		hummingbird.MetaLen + path.InfoLen*int(p.hbirdPath.PathMeta.CurrINF))
}

func (p *scionPacketProcessor) currentHbirdHopPointer() uint16 {
	return uint16(slayers.CmnHdrLen + p.scionLayer.AddrHdrLen() +
		hummingbird.MetaLen + path.InfoLen*p.hbirdPath.NumINF +
		hummingbird.LineLen*int(p.hbirdPath.PathMeta.CurrHF))
}

// Returns the ingress and egress through which the current packet enters and leves the AS
func (p *scionPacketProcessor) getFlyoverInterfaces() (uint16, uint16, disposition) {
	ingress := p.hopField.ConsIngress
	egress := p.hopField.ConsEgress
	// Reservations are not bidirectional,
	//   reservation ingress and egress are always real ingress and egress
	if !p.infoField.ConsDir {
		ingress, egress = egress, ingress
	}
	// On crossovers, A Reservation goes from the ingress of the incoming hop to
	//   the egress of the outgoing one
	var err error
	if p.hbirdPath.IsXover() && !p.peering {
		egress, err = p.hbirdPath.GetNextEgress()
		if err != nil {
			return 0, 0, errorDiscard("error", err)
		}
	} else if p.hbirdPath.IsFirstHopAfterXover() && !p.peering {
		ingress, err = p.hbirdPath.GetPreviousIngress()
		if err != nil {
			return 0, 0, errorDiscard("error", err)
		}
	}
	return ingress, egress, pForward
}

func (p *scionPacketProcessor) verifyHbirdScionMac() disposition {
	scionMac := path.FullMAC(p.mac, p.infoField, p.hopField, p.macInputBuffer[:path.MACBufferSize])
	verified := subtle.ConstantTimeCompare(p.hopField.Mac[:path.MacLen], scionMac[:path.MacLen])
	if verified == 0 {
		log.Debug("SCMP: MAC verification failed", "expected", fmt.Sprintf(
			"%x", scionMac[:path.MacLen]),
			"actual", fmt.Sprintf("%x", p.hopField.Mac[:path.MacLen]),
			"cons_dir", p.infoField.ConsDir,
			"if_id", p.ingressFromLink, "curr_inf", p.hbirdPath.PathMeta.CurrINF,
			"curr_hf", p.hbirdPath.PathMeta.CurrHF, "seg_id", p.infoField.SegID)
		p.pkt.slowPathRequest = slowPathRequest{
			spType:  slowPathType(slayers.SCMPTypeParameterProblem),
			code:    slayers.SCMPCodeInvalidHopFieldMAC,
			pointer: p.currentHopPointer(),
		}
		return pSlowPath
	}
	return pForward
}

func (p *scionPacketProcessor) verifyHbirdFlyoverMac() disposition {
	var flyoverMac []byte
	var verified int

	ingress, egress, disp := p.getFlyoverInterfaces()
	if disp != pForward {
		return disp
	}

	ak := hummingbird.DeriveAuthKey(p.prf, p.flyoverField.ResID, p.flyoverField.Bw,
		ingress, egress, p.hbirdPath.PathMeta.BaseTS-uint32(p.flyoverField.ResStartTime),
		p.flyoverField.Duration,
		p.macInputBuffer[path.MACBufferSize+hummingbird.FlyoverMacBufferSize:])
	flyoverMac = hummingbird.FullFlyoverMac(ak, p.scionLayer.DstIA, p.scionLayer.PayloadLen,
		p.flyoverField.ResStartTime, p.hbirdPath.PathMeta.HighResTS,
		p.macInputBuffer[path.MACBufferSize:], p.hbirdXkbuffer)

	if !p.hbirdPath.IsFirstHopAfterXover() {
		disp := p.updateHbirdNonConsDirIngressSegIDFlyover(flyoverMac)
		if disp != pForward {
			return disp
		}
	}
	scionMac := path.FullMAC(p.mac, p.infoField, p.hopField, p.macInputBuffer[:path.MACBufferSize])

	macXor(flyoverMac[:], scionMac[:], flyoverMac[:])
	verified = subtle.ConstantTimeCompare(p.hopField.Mac[:path.MacLen], flyoverMac[:path.MacLen])
	if verified == 0 {
		log.Debug("SCMP: Aggregate MAC verification failed",
			"expected", fmt.Sprintf("%x", flyoverMac[:path.MacLen]),
			"actual", fmt.Sprintf("%x", p.hopField.Mac[:path.MacLen]),
			"cons_dir", p.infoField.ConsDir,
			"scionMac", fmt.Sprintf("%x", scionMac[:path.MacLen]),
			"if_id", p.ingressFromLink, "curr_inf", p.hbirdPath.PathMeta.CurrINF,
			"curr_hf", p.hbirdPath.PathMeta.CurrHF, "seg_id", p.infoField.SegID,
			"packet length", p.scionLayer.PayloadLen,
			"dest", p.scionLayer.DstIA, "startTime", p.flyoverField.ResStartTime,
			"highResTS", p.hbirdPath.PathMeta.HighResTS,
			"ResID", p.flyoverField.ResID, "Bw", p.flyoverField.Bw,
			"in", p.hopField.ConsIngress, "Eg", p.hopField.ConsEgress,
			"start ak", p.hbirdPath.PathMeta.BaseTS-uint32(p.flyoverField.ResStartTime),
			"Duration", p.flyoverField.Duration)
	}

	// Add the full MAC to the SCION packet processor,
	// such that hummingbird mac de-aggregation do not need to recalculate it.
	// Do not overwrite cachedmac after doing xover, as it may contain a  flyovermac
	// This function is currently not called after a xover, so no need to check
	// Keep in mind for future changes
	p.cachedMac = scionMac

	if verified == 0 {
		p.pkt.slowPathRequest = slowPathRequest{
			spType:  slowPathType(slayers.SCMPTypeParameterProblem),
			code:    slayers.SCMPCodeInvalidHopFieldMAC,
			pointer: p.currentHopPointer(),
		}
		return pSlowPath
	}
	return pForward
}

func (p *scionPacketProcessor) validateHbirdSrcDstIA() disposition {
	srcIsLocal := (p.scionLayer.SrcIA == p.d.localIA)
	dstIsLocal := (p.scionLayer.DstIA == p.d.localIA)
	if p.ingressFromLink == 0 {
		// Outbound
		// Only check SrcIA if first hop, for transit this already checked by ingress router.
		// Note: SCMP error messages triggered by the sibling router may use paths that
		// don't start with the first hop.
		if p.hbirdPath.IsFirstHop() && !srcIsLocal {
			return p.respInvalidSrcIA()
		}
		if dstIsLocal {
			return p.respInvalidSrcIA()
		}
	} else {
		// Inbound
		if srcIsLocal {
			return p.respInvalidSrcIA()
		}
		if p.hbirdPath.IsLastHop() != dstIsLocal {
			return p.respInvalidDstIA()
		}
	}
	return pForward
}

func (p *scionPacketProcessor) ingressInterfaceHbird() uint16 {
	info := p.infoField
	hop := p.flyoverField
	if !p.peering && p.hbirdPath.IsFirstHopAfterXover() {
		var err error
		info, err = p.hbirdPath.GetInfoField(int(p.hbirdPath.PathMeta.CurrINF) - 1)
		if err != nil { // cannot be out of range
			panic(err)
		}
		// Previous hop should always be a non-flyover field,
		//  as flyover is transferred to second hop on xover
		hop, err = p.hbirdPath.GetHopField(int(p.hbirdPath.PathMeta.CurrHF) - hummingbird.HopLines)
		if err != nil { // cannot be out of range
			panic(err)
		}
	}
	if info.ConsDir {
		return hop.HopField.ConsIngress
	}
	return hop.HopField.ConsEgress
}

// validateTransitUnderlaySrc checks that the source address of transit packets
// matches the expected sibling router.
// Provided that underlying network infrastructure prevents address spoofing,
// this check prevents malicious end hosts in the local AS from bypassing the
// SrcIA checks by disguising packets as transit traffic.
func (p *scionPacketProcessor) validateHbirdTransitUnderlaySrc() disposition {
	if p.hbirdPath.IsFirstHop() || p.ingressFromLink != 0 {
		// Locally originated traffic, or came in via an external link. Not our concern.
		return pForward
	}
	pktIngressID := p.ingressInterfaceHbird()   // Where this was *supposed* to enter the AS
	ingressLink := p.d.interfaces[pktIngressID] // Our own link to *that* sibling router

	// Is that the link that the packet came through (e.g. not the internal link)? The
	// comparison should be cheap. Links are implemented by pointers.
	if ingressLink != p.pkt.Link {
		// Drop
		return errorDiscard("error", errInvalidSrcAddrForTransit)
	}
	return pForward
}

// Verifies the PathMetaHeader timestamp is recent
// Current implementation works with a nanosecond granularity HighResTS
func (p *scionPacketProcessor) validatePathMetaTimestamp() {
	timestamp := util.SecsToTime(p.hbirdPath.PathMeta.BaseTS).Add(
		time.Duration(p.hbirdPath.PathMeta.HighResTS>>22) * time.Millisecond)
	// TODO: make a configurable value instead of using a flat 1 seconds
	if time.Until(timestamp).Abs() > time.Duration(1)*time.Second {
		// Hummingbird specification explicitly says to forward best-effort is timestamp too old
		p.hasPriority = false
	}
}

// Converts a flyover bandwidth value to bytes per second
func convertResBw(bw uint16) float64 {

	// In this implementation, we choose to allow reservations up to 64 kBps
	// Since the bandwidth field has 10 bits, we multiply by 64 to reach the target range
	return float64(bw * 64)
}

func (p *scionPacketProcessor) checkReservationBandwidth() disposition {
	// Only check bandwidth if packet is given priority
	// Bandwidth check is NOT performed for late packets that have flyover but no priority
	if !p.hasPriority {
		return pForward
	}
	// resID only has to be unique per interface pair
	// key for the tokenbuckets map is based on flyover resID, ingress and egress
	ingress, egress, disp := p.getFlyoverInterfaces()
	if disp != pForward {
		return disp
	}

	// Get the token bucket or add a new one.
	resKey := uint64(p.flyoverField.ResID) + uint64(ingress)<<22 + uint64(egress)<<38
	resBw := convertResBw(p.flyoverField.Bw)
	now := time.Now()
	v, _ := p.d.tokenBuckets.LoadOrStore(
		resKey,
		tokenbucket.NewTokenBucket(now, resBw, resBw))
	tb, ok := v.(*tokenbucket.TokenBucket)
	if !ok {
		log.Error("Non-tokenbucket value found in tokenbucket map")
		// This is an internal error that should never happen. We can't verify the BW.
		return pForward
	}

	// Check bandwidth
	if tb.CIR != resBw {
		// It is possible for different reservations to share a resID
		// if they do not overlap in time.
		tb.SetRate(resBw)
		tb.SetBurstSize(resBw)
	}
	if tb.Apply(int(p.scionLayer.PayloadLen), time.Now()) {
		return pForward
	}
	// TODO: introduce priorities
	return pForward

}

func (p *scionPacketProcessor) handleHbirdIngressRouterAlert() disposition {
	if p.ingressFromLink == 0 {
		return pForward
	}
	alert := p.ingressRouterAlertFlag()
	if !*alert {
		return pForward
	}
	// We have an alert.
	*alert = false
	err := p.hbirdPath.SetHopField(p.flyoverField, int(p.hbirdPath.PathMeta.CurrHF))
	if err != nil {
		return errorDiscard("error", err)
	}
	p.pkt.slowPathRequest = slowPathRequest{
		spType: slowPathRouterAlertIngress,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) handleHbirdEgressRouterAlert() disposition {
	alert := p.egressRouterAlertFlag()
	if !*alert {
		return pForward
	}
	if p.d.interfaces[p.pkt.egress].Scope() != External {
		// the egress router is not this one.
		return pForward
	}
	*alert = false
	err := p.hbirdPath.SetHopField(p.flyoverField, int(p.hbirdPath.PathMeta.CurrHF))
	if err != nil {
		return errorDiscard("error", err)
	}
	p.pkt.slowPathRequest = slowPathRequest{
		spType: slowPathRouterAlertEgress,
	}
	return pSlowPath
}

func (p *scionPacketProcessor) updateHbirdNonConsDirIngressSegIDFlyover(flyoverMac []byte) disposition {
	// against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	// If a flyover is present, need to first de-aggregate the first two bytes of the mac
	// before updating SegID
	if !p.infoField.ConsDir && p.ingressFromLink != 0 && !p.peering {
		// de-aggregate first two bytes of mac
		p.hopField.Mac[0] ^= flyoverMac[0]
		p.hopField.Mac[1] ^= flyoverMac[1]
		p.infoField.UpdateSegID(p.hopField.Mac)
		// restore correct state of MAC field, even if error
		p.hopField.Mac[0] ^= flyoverMac[0]
		p.hopField.Mac[1] ^= flyoverMac[1]
		err := p.hbirdPath.SetInfoField(p.infoField, int(p.hbirdPath.PathMeta.CurrINF))
		if err != nil {
			return errorDiscard("error", err)
		}
	}
	return pForward
}

func (p *scionPacketProcessor) updateHbirdNonConsDirIngressSegID() disposition {
	// against construction dir the ingress router updates the SegID, ifID == 0
	// means this comes from this AS itself, so nothing has to be done.
	if !p.infoField.ConsDir && p.ingressFromLink != 0 && !p.peering {
		p.infoField.UpdateSegID(p.hopField.Mac)
		err := p.hbirdPath.SetInfoField(p.infoField, int(p.hbirdPath.PathMeta.CurrINF))
		if err != nil {
			return errorDiscard("error", err)
		}
	}
	return pForward
}

// macXor XORs a and b and writes the result into d.
// Expects all arguments to have a length of macLen
func macXor(d, a, b []byte) {
	for i := 0; i < path.MacLen; i++ {
		d[i] = a[i] ^ b[i]
	}
}

func (p *scionPacketProcessor) deAggregateMac() disposition {
	if !p.flyoverField.Flyover {
		return pForward
	}
	copy(p.hopField.Mac[:], p.cachedMac[:path.MacLen])
	if err := p.hbirdPath.ReplaceCurrentMac(p.cachedMac); err != nil {
		log.Debug("Failed to replace MAC after de-aggregation", "error", err.Error())
		return errorDiscard("error", fmt.Errorf("MAC replacement failed"))
	}
	return pForward
}

// de-aggregates mac and stores the flyovermac part of the mac in cachedMac
func (p *scionPacketProcessor) deAggregateAndCacheMac() disposition {
	if !p.flyoverField.Flyover {
		return pForward
	}
	// obtain flyoverMac and buffer in macInputBuffer
	// such that it is not overwritten by the following standard mac computation
	macXor(p.macInputBuffer[path.MACBufferSize:], p.cachedMac, p.hopField.Mac[:])
	// deaggregate Mac
	copy(p.hopField.Mac[:], p.cachedMac[:path.MacLen])
	if err := p.hbirdPath.ReplaceCurrentMac(p.cachedMac); err != nil {
		log.Debug("Failed to replace MAC after de-aggregation", "error", err.Error())
		return errorDiscard("error", fmt.Errorf("MAC replacement failed"))
	}
	// set cachedMac to the buffered flyoverMac
	p.cachedMac = p.macInputBuffer[path.MACBufferSize : path.MACBufferSize+path.MacLen]
	return pForward
}

// xoverMoveFlyoverToNext is called during ASTransit incoming BR. It moves the flyover hopfield
// to the next hopfield, so that the ASTransit outgoing BR forwards it with priority.
func (p *scionPacketProcessor) xoverMoveFlyoverToNext() disposition {
	// Move flyoverhopfield to next hop for benefit of egress router
	if err := p.hbirdPath.MoveFlyoverToNext(); err != nil {
		return errorDiscard("error", err)
	}

	// Aggregate mac of current hopfield with buffered flyoverMac
	mac, err := p.hbirdPath.GetMac(int(p.hbirdPath.PathMeta.CurrHF))
	if err != nil {
		return errorDiscard("error", err)
	}
	macXor(mac, mac, p.cachedMac)
	return pForward
}

func (p *scionPacketProcessor) xoverMoveFlyoverToPrevious() disposition {
	if err := p.hbirdPath.MoveFlyoverToPrevious(); err != nil {
		return errorDiscard("error", err)
	}
	// No MAC aggregation/de-aggregation, as these are already performed
	p.flyoverField.Flyover = false
	return pForward
}

func (p *scionPacketProcessor) doHbirdXoverFlyover() disposition {
	p.effectiveXover = true
	p.isFlyoverXover = true

	if disp := p.deAggregateAndCacheMac(); disp != pForward {
		return disp
	}

	if err := p.hbirdPath.IncPath(hummingbird.FlyoverLines); err != nil {
		return errorDiscard("error", err)
	}

	var err error
	if p.flyoverField, err = p.hbirdPath.GetCurrentHopField(); err != nil {
		return errorDiscard("error", err)
	}
	if p.infoField, err = p.hbirdPath.GetCurrentInfoField(); err != nil {
		return errorDiscard("error", err)
	}
	p.hopField = p.flyoverField.HopField
	return pForward
}

func (p *scionPacketProcessor) doHbirdXoverBestEffort() disposition {
	p.effectiveXover = true

	if err := p.hbirdPath.IncPath(hummingbird.HopLines); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}

	var err error
	if p.flyoverField, err = p.hbirdPath.GetCurrentHopField(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	if p.infoField, err = p.hbirdPath.GetCurrentInfoField(); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	p.hopField = p.flyoverField.HopField
	return pForward
}

func (p *scionPacketProcessor) processHbirdEgress() disposition {
	// We are the egress router and if we go in construction direction we
	// need to update the SegID (unless we are effecting a peering hop).
	// When we're at a peering hop, the SegID for this hop and for the next
	// are one and the same, both hops chain to the same parent. So do not
	// update SegID.
	if p.infoField.ConsDir && !p.peering {
		p.infoField.UpdateSegID(p.hopField.Mac)
		if err := p.hbirdPath.SetInfoField(
			p.infoField, int(p.hbirdPath.PathMeta.CurrINF)); err != nil {
			// TODO parameter problem invalid path
			return errorDiscard("error", err)
		}
	}
	n := hummingbird.HopLines
	if p.flyoverField.Flyover {
		n = hummingbird.FlyoverLines
	}
	if err := p.hbirdPath.IncPath(n); err != nil {
		// TODO parameter problem invalid path
		return errorDiscard("error", err)
	}
	return pForward
}

// func (p *scionPacketProcessor) processHummingbird() (processResult, error) {
func (p *scionPacketProcessor) processHummingbird() disposition {
	var ok bool
	p.hbirdPath, ok = p.scionLayer.Path.(*hummingbird.Raw)
	if !ok {
		// TODO(lukedirtwalker) parameter problem invalid path?
		return errorDiscard("error", errMalformedPath)
	}
	if disp := p.parseHbirdPath(); disp != pForward {
		return disp
	}
	if disp := p.determinePeerHbird(); disp != pForward {
		return disp
	}
	// deleteme uncomment
	if disp := p.validateHopExpiryHbird(); disp != pForward {
		return disp
	}
	if disp := p.validateIngressID(); disp != pForward {
		return disp
	}
	if disp := p.validatePktLen(); disp != pForward {
		return disp
	}
	if disp := p.validateHbirdTransitUnderlaySrc(); disp != pForward {
		return disp
	}
	if disp := p.validateHbirdSrcDstIA(); disp != pForward {
		return disp
	}
	if disp := p.validateSrcHost(); disp != pForward {
		return disp
	}
	if p.flyoverField.Flyover {
		return p.processHBIRDFlyover()
	}
	return p.processHBIRDBestEffort()
}

func (p *scionPacketProcessor) processHBIRDFlyover() disposition {
	// deleteme uncomment
	if disp := p.validateReservationExpiry(); disp != pForward {
		return disp
	}
	if disp := p.verifyHbirdFlyoverMac(); disp != pForward {
		return disp
	}
	p.validatePathMetaTimestamp()
	if disp := p.checkReservationBandwidth(); disp != pForward {
		return disp
	}
	if disp := p.handleHbirdIngressRouterAlert(); disp != pForward {
		return disp
	}
	// Inbound: pkts destined to the local IA.
	if p.scionLayer.DstIA == p.d.localIA {
		if disp := p.deAggregateMac(); disp != pForward {
			return disp
		}
		disp := p.resolveInbound()
		if disp != pForward {
			return disp
		}
		p.pkt.trafficType = ttIn
		return pForward
	}

	// Outbound: pkt leaving the local IA. This Could be:
	// * Pure outbound: from this AS, in via internal, out via external.
	// * ASTransit in: from another AS, in via external, out via internal to other BR.
	// * ASTransit out: from another AS, in via internal from other BR, out via external.
	// * BRTransit: from another AS, in via external, out via external.
	if p.hbirdPath.IsXover() && !p.peering {
		// An effective cross-over is a change of segment other than at
		// a peering hop.
		if disp := p.doHbirdXoverFlyover(); disp != pForward {
			return disp
		}
		// doXover() has changed the current segment and hop field.
		// We need to validate the new hop field.
		if disp := p.validateHopExpiry(); disp != pForward {
			return disp
		}
		// verify the new hopField
		if disp := p.verifyHbirdScionMac(); disp != pForward {
			return disp
		}
	}
	egressID := p.egressInterface()
	p.pkt.egress = egressID
	if disp := p.validateEgressID(); disp != pForward {
		return disp
	}

	// handle egress router alert before we check if it's up because we want to
	// send the reply anyway, so that trace route can pinpoint the exact link
	// that failed.
	if disp := p.handleHbirdEgressRouterAlert(); disp != pForward {
		return disp
	}
	if disp := p.validateEgressUp(); disp != pForward {
		return disp
	}

	if p.d.interfaces[egressID].Scope() == External {
		// Not ASTransit in.
		if disp := p.deAggregateMac(); disp != pForward {
			return disp
		}
		if p.hbirdPath.IsFirstHopAfterXover() && !p.effectiveXover && !p.peering {
			if disp := p.xoverMoveFlyoverToPrevious(); disp != pForward {
				return disp
			}
		}
		if disp := p.processHbirdEgress(); disp != pForward {
			return disp
		}
		// Finish deciding the trafficType...
		var tt trafficType
		if p.scionLayer.SrcIA == p.d.localIA {
			// Pure outbound
			tt = ttOut
		} else if p.ingressFromLink == 0 {
			// ASTransit out
			tt = ttOutTransit
		} else {
			// Therefore it is BRTransit
			tt = ttBrTransit
		}
		p.pkt.trafficType = tt
		return pForward
	}
	// ASTransit in: pkt leaving this AS through another BR.
	// We already know the egressID is valid. The packet can go straight to forwarding.
	if p.isFlyoverXover {
		if disp := p.xoverMoveFlyoverToNext(); disp != pForward {
			return disp
		}
	}
	p.pkt.trafficType = ttInTransit
	return pForward
}

func (p *scionPacketProcessor) processHBIRDBestEffort() disposition {
	if disp := p.updateHbirdNonConsDirIngressSegID(); disp != pForward {
		return disp
	}
	if disp := p.verifyHbirdScionMac(); disp != pForward {
		return disp
	}
	if disp := p.handleHbirdIngressRouterAlert(); disp != pForward {
		return disp
	}
	// Inbound: pkts destined to the local IA.
	if p.scionLayer.DstIA == p.d.localIA {
		disp := p.resolveInbound()
		if disp != pForward {
			return disp
		}
		p.pkt.trafficType = ttIn
		return pForward
	}

	// Outbound: pkt leaving the local IA. This Could be:
	// * Pure outbound: from this AS, in via internal, out via external.
	// * ASTransit in: from another AS, in via external, out via internal to other BR.
	// * ASTransit out: from another AS, in via internal from other BR, out via external.
	// * BRTransit: from another AS, in via external, out via external.
	if p.hbirdPath.IsXover() && !p.peering {
		if disp := p.doHbirdXoverBestEffort(); disp != pForward {
			return disp
		}
		if disp := p.validateHopExpiryHbird(); disp != pForward {
			return disp
		}
		// verify the new hopField
		if disp := p.verifyHbirdScionMac(); disp != pForward {
			return disp
		}
	}
	egressID := p.egressInterface()
	p.pkt.egress = egressID
	if disp := p.validateEgressID(); disp != pForward {
		return disp
	}

	// handle egress router alert before we check if it's up because we want to
	// send the reply anyway, so that trace route can pinpoint the exact link
	// that failed.
	if disp := p.handleHbirdEgressRouterAlert(); disp != pForward {
		return disp
	}
	if disp := p.validateEgressUp(); disp != pForward {
		return disp
	}

	if p.d.interfaces[egressID].Scope() == External {
		if disp := p.processHbirdEgress(); disp != pForward {
			return disp
		}
		// Finish deciding the trafficType...
		var tt trafficType
		if p.scionLayer.SrcIA == p.d.localIA {
			// Pure outbound
			tt = ttOut
		} else if p.ingressFromLink == 0 {
			// ASTransit out
			tt = ttOutTransit
		} else {
			// Therefore it is BRTransit
			tt = ttBrTransit
		}
		p.pkt.trafficType = tt
		return pForward
	}

	// ASTransit in: pkt leaving this AS through another BR.
	// We already know the egressID is valid. The packet can go straight to forwarding.
	p.pkt.trafficType = ttInTransit
	return pForward
}

// Functions for SCMP packets preparation

func (p *slowPathPacketProcessor) prepareHbirdSCMP(
	typ slayers.SCMPType,
	code slayers.SCMPCode,
	scmpP gopacket.SerializableLayer,
	isError bool,
) error {
	path, ok := p.scionLayer.Path.(*hummingbird.Raw)
	if !ok {
		return serrors.JoinNoStack(errCannotRoute, nil, "details", "unsupported path type",
			"path type", p.scionLayer.Path.Type())
	}

	decPath, err := path.ToDecoded()
	if err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "decoding raw path")
	}
	revPathTmp, err := decPath.Reverse()
	if err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "reversing path for SCMP")
	}
	revPath := revPathTmp.(*hummingbird.Decoded)

	peering, err := determinePeerHbird(revPath.PathMeta, revPath.InfoFields[revPath.PathMeta.CurrINF])
	if err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "peering cannot be determined")
	}

	// Revert potential path segment switches that were done during processing.
	if revPath.IsXover() && !peering {
		// An effective cross-over is a change of segment other than at
		// a peering hop.
		if err := revPath.IncPath(hummingbird.HopLines); err != nil {
			return serrors.JoinNoStack(errCannotRoute, err,
				"details", "reverting cross over for SCMP")
		}
	}
	// If the packet is sent to an external router, we need to increment the
	// path to prepare it for the next hop.
	// This is an SCMP response to pkt, so the egress link will be the ingress link.
	if p.pkt.Link.Scope() == External {
		infoField := &revPath.InfoFields[revPath.PathMeta.CurrINF]
		if infoField.ConsDir && !peering {
			hopField := revPath.HopFields[revPath.PathMeta.CurrHF]
			infoField.UpdateSegID(hopField.HopField.Mac)
		}
		if err := revPath.IncPath(hummingbird.HopLines); err != nil {
			return serrors.JoinNoStack(errCannotRoute, err,
				"details", "incrementing path for SCMP")
		}
	}

	// create new SCION header for reply.
	var scionL slayers.SCION
	scionL.FlowID = p.scionLayer.FlowID
	scionL.TrafficClass = p.scionLayer.TrafficClass
	scionL.PathType = revPath.Type()
	scionL.Path = revPath
	scionL.DstIA = p.scionLayer.SrcIA
	scionL.SrcIA = p.d.localIA
	scionL.DstAddrType = p.scionLayer.SrcAddrType
	scionL.RawDstAddr = p.scionLayer.RawSrcAddr
	scionL.NextHdr = slayers.L4SCMP

	if err := scionL.SetSrcAddr(p.d.localHost); err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "setting src addr")
	}
	typeCode := slayers.CreateSCMPTypeCode(typ, code)
	scmpH := slayers.SCMP{TypeCode: typeCode}
	scmpH.SetNetworkLayerForChecksum(&scionL)

	needsAuth := false
	if p.d.ExperimentalSCMPAuthentication {
		// Error messages must be authenticated.
		// Traceroute are OPTIONALLY authenticated ONLY IF the request
		// was authenticated.
		// TODO(JordiSubira): Reuse the key computed in p.hasValidAuth
		// if SCMPTypeTracerouteReply to create the response.
		needsAuth = isError ||
			(scmpH.TypeCode.Type() == slayers.SCMPTypeTracerouteReply &&
				p.hasValidAuth(time.Now()))
	}

	sopts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}
	var serBuf serializeProxy

	// First write the SCMP message only without the SCION header(s) to get a buffer that we can
	// feed to the MAC computation. If this is an error response, then it has to include a quote of
	// the packet at the end of the SCMP message.

	if isError {
		// There is headroom built into the packet buffer so we can wrap the whole packet into a new
		// one without copying it. We need to reclaim that headroom so we can prepend. We can figure
		// the current headroom, even if it was changed, by comparing the capacity of the slice with
		// our constant buffer size.
		quoteLen := len(p.pkt.RawPacket)
		headroom := len(p.pkt.buffer) - cap(p.pkt.RawPacket)
		hdrLen := slayers.CmnHdrLen + scionL.AddrHdrLen() + scionL.Path.Len() +
			slayers.ScmpHeaderSize(scmpH.TypeCode.Type())

		if needsAuth {
			hdrLen += e2eAuthHdrLen
		}
		maxQuoteLen := slayers.MaxSCMPPacketLen - hdrLen
		if quoteLen > maxQuoteLen {
			quoteLen = maxQuoteLen
		}
		// Now that we know the length, we can serialize the SCMP headers and the quoted packet. If
		// we don't fit in the headroom we copy the quoted packet to the end. We are required to
		// leave space for a worst-case underlay header too. TODO(multi_underlay): since we know
		// that this goes back via the link it came from, we could be content with leaving just
		// enough headroom for this specific underlay.
		if hdrLen+p.d.underlayHeadroom > headroom {
			// Not enough headroom. Pack at end.
			quote := p.pkt.RawPacket[:quoteLen]
			serBuf = newSerializeProxy(p.pkt.RawPacket)
			err = gopacket.SerializeLayers(&serBuf, sopts, &scmpH, scmpP, gopacket.Payload(quote))
			if err != nil {
				return serrors.JoinNoStack(
					errCannotRoute, err, "details", "serializing SCMP message")
			}
		} else {
			// Serialize in front of the quoted packet. The quoted packet must be included in the
			// serialize buffer before we pack the SCMP header in from of it. AppendBytes will do
			// that; it exposes the underlying buffer but doesn't modify it.
			p.pkt.RawPacket = p.pkt.buffer[0:(quoteLen + headroom)]
			serBuf = newSerializeProxyStart(p.pkt.RawPacket, headroom)
			_, _ = serBuf.AppendBytes(quoteLen) // Implementation never fails.
			err = scmpP.SerializeTo(&serBuf, sopts)
			if err != nil {
				return serrors.JoinNoStack(
					errCannotRoute, err, "details", "serializing SCMP message")
			}
			err = scmpH.SerializeTo(&serBuf, sopts)
			if err != nil {
				return serrors.JoinNoStack(
					errCannotRoute, err, "details", "serializing SCMP message")
			}
		}
	} else {
		// We do not need to preserve the packet. Just pack our headers at the end of the buffer.
		// (this is what serializeProxy does by default).
		serBuf = newSerializeProxy(p.pkt.RawPacket)
		err = gopacket.SerializeLayers(&serBuf, sopts, &scmpH, scmpP)
		if err != nil {
			return serrors.JoinNoStack(errCannotRoute, err, "details", "serializing SCMP message")
		}
	}

	// serBuf now starts with the SCMP Headers and ends with the truncated quoted packet, if any.
	// This is what gets checksumed.
	if needsAuth {
		var e2e slayers.EndToEndExtn
		scionL.NextHdr = slayers.End2EndClass

		now := time.Now()
		dstA, err := scionL.DstAddr()
		if err != nil {
			return serrors.JoinNoStack(errCannotRoute, err,
				"details", "parsing destination address")
		}
		key, err := p.drkeyProvider.GetASHostKey(now, scionL.DstIA, dstA)
		if err != nil {
			return serrors.JoinNoStack(errCannotRoute, err, "details", "retrieving DRKey")
		}
		if err := p.resetSPAOMetadata(key, now); err != nil {
			return serrors.JoinNoStack(errCannotRoute, err, "details", "resetting SPAO header")
		}

		e2e.Options = []*slayers.EndToEndOption{p.optAuth.EndToEndOption}
		e2e.NextHdr = slayers.L4SCMP
		_, err = spao.ComputeAuthCMAC(
			spao.MACInput{
				Key:        key.Key[:],
				Header:     p.optAuth,
				ScionLayer: &scionL,
				PldType:    slayers.L4SCMP,
				Pld:        serBuf.Bytes(),
			},
			p.macInputBuffer,
			p.optAuth.Authenticator(),
		)
		if err != nil {
			return serrors.JoinNoStack(errCannotRoute, err, "details", "computing CMAC")
		}
		if err := e2e.SerializeTo(&serBuf, sopts); err != nil {
			return serrors.JoinNoStack(errCannotRoute, err,
				"details", "serializing SCION E2E headers")
		}
	} else {
		scionL.NextHdr = slayers.L4SCMP
	}

	// Our SCION header is ready. Prepend it.
	if err := scionL.SerializeTo(&serBuf, sopts); err != nil {
		return serrors.JoinNoStack(errCannotRoute, err, "details", "serializing SCION header")
	}

	// serBuf now has the exact slice that represents the packet.
	p.pkt.RawPacket = serBuf.Bytes()

	log.Debug("SCMP", "typecode", scmpH.TypeCode)
	return nil
}

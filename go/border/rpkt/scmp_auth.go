// Copyright 2017 ETH Zurich
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

// This file handles packet processing.

package rpkt

import (
	"bytes"
	"hash"

	"github.com/netsec-ethz/scion/go/lib/addr"
	"github.com/netsec-ethz/scion/go/lib/common"
	"github.com/netsec-ethz/scion/go/lib/drkey"
	"github.com/netsec-ethz/scion/go/lib/spkt"
	"github.com/netsec-ethz/scion/go/lib/spse"
	"github.com/netsec-ethz/scion/go/lib/spse/scmp_auth"
	"github.com/netsec-ethz/scion/go/lib/util"
)

// AuthenticateSCMP finds the SCMP Auth extensions and authenticates them.
func (r *RtrPkt) AuthenticateSCMP(e2eParsed bool) *common.Error {
	var drkeyExtn *rSCMPAuthDRKeyExtn
	var err *common.Error
	if e2eParsed {
		drkeyExtn, _, err = r.FindParsedSCMPAuthExtns()
	} else {
		drkeyExtn, _, err = r.FindSCMPAuthExtns()
	}
	if err != nil {
		return err
	}
	return drkeyExtn.Authenticate()
}

// AuthenticateSCMPAuthExt computes the MAC and inserts it into the extensions.
// SCMP packets are authenticated with the key S -> D:HD.
func (s *rSCMPAuthDRKeyExtn) Authenticate() *common.Error {
	s.SetDirection(scmp_auth.AsToHost)
	s.ResetMac()
	key, err := s.rp.calcSCMPAuthDRKey(s.rp.dstIA, s.rp.dstHost)
	if err != nil {
		return err
	}
	mac, err := s.rp.calcSCMPAuthMac(key)
	if err != nil {
		return err
	}
	if err = s.SetMAC(mac); err != nil {
		return err
	}
	return nil
}

// VerifySCMPAuthExt computes the MAC and compares it to the one in the packet.
// SCMP packets to the BR hav to be authenticated with the key S:HS -> D.
func (s *rSCMPAuthDRKeyExtn) VerifyMAC() *common.Error {
	if s.Direction() != scmp_auth.HostToAs {
		return common.NewError("Invalid SCMPAuthDRKey direction", "expected",
			scmp_auth.HostToAs, "actual", s.Direction())
	}
	orig := make(common.RawBytes, scmp_auth.MACLength)
	copy(orig, s.MAC())
	s.ResetMac()
	defer s.SetMAC(orig)
	key, err := s.rp.calcSCMPAuthDRKey(s.rp.srcIA, s.rp.srcHost)
	if err != nil {
		return err
	}
	mac, err := s.rp.calcSCMPAuthMac(key)
	if err != nil {
		return err
	}
	if !bytes.Equal(mac, orig) {
		return common.NewError("Invalid SCMPAuthDRKey MAC", "expected", mac, "actual", orig)
	}
	return nil

}

// findSCMPAuthExtns walks the header chain, searching for SCMPAuth extensions.
func (rp *RtrPkt) FindSCMPAuthExtns() (*rSCMPAuthDRKeyExtn, *rSCMPAuthHashTreeExtn, *common.Error) {
	var drkeyExtn *rSCMPAuthDRKeyExtn
	var hashtreeExtn *rSCMPAuthHashTreeExtn

	for i, idx := range rp.idxs.e2eExt {
		if idx.Type != common.ExtnSCIONPacketSecurityType {
			continue
		}
		start := idx.Index + common.ExtnSubHdrLen
		end := rp.idxs.l4
		if i < len(rp.idxs.e2eExt)-1 {
			end = rp.idxs.e2eExt[i+1].Index
		}
		switch spse.SecMode(rp.Raw[start]) {
		case spse.ScmpAuthDRKey:
			if drkeyExtn != nil {
				return nil, nil, common.NewError("Multiple SCMPAuthDRKeyExtensions")
			}
			extn, err := rSCMPAuthDRKeyExtnFromRaw(rp, start, end)
			if err != nil {
				return nil, nil, err
			}
			drkeyExtn = extn
		case spse.ScmpAuthHashTree:
			if hashtreeExtn != nil {
				return nil, nil, common.NewError("Multiple SCMPAuthHashTreeExtensions")
			}
			extn, err := rSCMPAuthHashTreeExtnFromRaw(rp, start, end)
			if err != nil {
				return nil, nil, err
			}
			hashtreeExtn = extn
		}
	}
	if drkeyExtn == nil && hashtreeExtn == nil {
		return nil, nil, common.NewError("No SCMPAuth extension")
	}
	return drkeyExtn, hashtreeExtn, nil
}

// findSCMPAuthExtns checks the parsed end-to-end extensions, searching for SCMPAuth extensions.
func (rp *RtrPkt) FindParsedSCMPAuthExtns() (*rSCMPAuthDRKeyExtn, *rSCMPAuthHashTreeExtn, *common.Error) {
	var drkeyExtn *rSCMPAuthDRKeyExtn
	var hashtreeExtn *rSCMPAuthHashTreeExtn

	for _, extn := range rp.E2EExt {
		if e, ok := extn.(*rSCMPAuthDRKeyExtn); ok {
			if drkeyExtn != nil {
				return nil, nil, common.NewError("Multiple SCMPAuthDRKeyExtensions")
			}
			drkeyExtn = e
		}
		if e, ok := extn.(*rSCMPAuthHashTreeExtn); ok {
			if hashtreeExtn != nil {
				return nil, nil,
					common.NewError("Multiple SCMPAuthHashtreeExtensions")
			}
			hashtreeExtn = e
		}
	}
	if drkeyExtn == nil && hashtreeExtn == nil {
		return nil, nil, common.NewError("No SCMPAuth extension")
	}
	return drkeyExtn, hashtreeExtn, nil
}

// calcSCMPAuthDRKey calculates the SCMPAuth DRKey for this packet.
func (rp *RtrPkt) calcSCMPAuthDRKey(dstIA *addr.ISD_AS, dstHost addr.HostAddr) (common.RawBytes, *common.Error) {
	all := make(common.RawBytes, 16)
	common.Order.PutUint32(all, uint32(dstIA.I))
	common.Order.PutUint32(all[4:], uint32(dstIA.A))
	mac := rp.Ctx.Conf.DRKeyPool.Get().(hash.Hash)
	key, err := util.Mac(mac, all)
	rp.Ctx.Conf.DRKeyPool.Put(mac)
	if err != nil {
		return nil, err
	}

	mac, err = util.InitMac(key)
	if err != nil {
		return nil, err
	}

	inputType, err := drkey.InputTypeFromHostTypes(dstHost.Type(), 0)
	size := 16
	if inputType.RequiredLength() > 10 {
		size = 32
	}

	all = make(common.RawBytes, size)
	all[0] = uint8(inputType)
	all[1] = 4 // length b"SCMP"
	copy(all[2:6], []byte("SCMP"))
	copy(all[6:], dstHost.Pack())
	return util.Mac(mac, all)
}

// CalcSCMPAuthMac calculates the SCMPAuthMac for his packet.
// The SCMPAuthExtns are assumed to be set appropriately.
func (rp *RtrPkt) calcSCMPAuthMac(drkey common.RawBytes) (common.RawBytes, *common.Error) {
	mac, err := util.InitMac(drkey)
	if err != nil {
		return nil, err
	}

	// Common Header and HBH extensions are not authenticated
	size := len(rp.Raw) - spkt.CmnHdrLen
	offsetHBH := rp.idxs.hbhExt[0].Index
	offsetE2E := rp.idxs.e2eExt[0].Index
	size -= (offsetE2E - offsetHBH)
	blkSize := mac.BlockSize()
	numBlocks := size / blkSize
	if len(rp.Raw)%blkSize != 0 {
		numBlocks++
	}

	all := make(common.RawBytes, numBlocks*blkSize)
	copy(all[:offsetHBH-spkt.CmnHdrLen], rp.Raw[spkt.CmnHdrLen:offsetHBH])
	copy(all[offsetHBH-spkt.CmnHdrLen:], rp.Raw[offsetE2E:])
	return util.Mac(mac, all)
}

// Copyright 2026 ETH Zurich
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

package path

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers"
	dppath "github.com/scionproto/scion/pkg/slayers/path"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	dphum "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	dphumm "github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
)

// Reservation is the snet path for a Hummingbird reservation path type.
// When creating a packet with a Reservation path, the flyover fields must contain the MAC that
// was computed using the correct payload size.
// This path represents a possibly partially reserved path, with zero or more flyovers.
type Reservation struct {
	DstIA addr.IA        // Destination IA of the path.
	Dec   *dphum.Decoded // The Hummingbird path.
	Hops  []*Hop         // Same length as `Dec`. Hops[i]==nil iff no hop at i (eg. xover hop).

	reverseReservation     *slayers.EndToEndExtn
	sentToPacketReverseRsv *slayers.EndToEndExtn
	blocksPerAk            []cipher.Block        // Same length as Hops.
	scionMacs              [][dppath.MacLen]byte // Original MAC fields from the SCION path.
	counter                uint32                // duplicate detection counter.
}

var _ snet.DataplanePath = (*Reservation)(nil)
var _ snet.DataplanePacketExtender = (*Reservation)(nil)

// NewReservation builds a new Hummingbird Reservation based on the destination IA and the
// options passed.
func NewReservation(opts ...ReservationModFcn) (*Reservation, error) {
	r := &Reservation{
		Dec: &dphum.Decoded{},
	}
	// Run all options on this object.
	for _, fcn := range opts {
		if err := fcn(r); err != nil {
			return nil, err
		}
	}

	if len(r.Hops) != len(r.Dec.HopFields) {
		return nil, serrors.New("wrong number of flyover",
			"expected", len(r.Dec.HopFields),
			"got", len(r.Hops))
	}

	if r.DstIA == 0 {
		return nil, serrors.New("unset destination IA")
	}

	return r, nil
}

// SetPath sets the path into the passed-by-pointer scion headers.
// When called, the scion layer has its fields (e.g. payload length, src IA, etc.) already set up.
func (r *Reservation) SetPath(s *slayers.SCION) error {
	// We need to have a path set in the slayers.SCION to compute its full packet length,
	// since r.Dec and the derived dataplane path have the same length in bytes,
	// use the decoded Hummingbird path initially before deriving the correct dataplane path.
	s.Path, s.PathType = r.Dec, r.Dec.Type()
	pktLen := s.PacketLen()
	r.deriveDataPlanePath(pktLen, time.Now())

	// The correct dataplane path in the SCION layer is still r.Dec (pointer to path),
	// nothing else to do.
	return nil
}

// SetReverseReservationExtn installs the reverse-reservation E2E extension to
// advertise on the next packet serialized over this reservation.
func (r *Reservation) SetReverseReservationExtn(extn *slayers.EndToEndExtn) {
	r.reverseReservation = extn
	r.sentToPacketReverseRsv = nil
}

// EndToEndExtn returns the reverse-reservation extension to be serialized with
// the next packet, if any.
func (r *Reservation) EndToEndExtn() (*slayers.EndToEndExtn, error) {
	if r.reverseReservation == nil {
		return nil, nil
	}
	if r.reverseReservation == r.sentToPacketReverseRsv {
		r.reverseReservation = nil
		r.sentToPacketReverseRsv = nil
		return nil, nil
	}
	r.sentToPacketReverseRsv = r.reverseReservation
	return r.reverseReservation, nil
}

// deriveDataPlanePath sets pathmeta timestamps and increments the duplicate detection counter and
// updates MACs of all flyoverfields using the full SCION packet length.
func (r *Reservation) deriveDataPlanePath(
	pktLen uint16,
	timeStamp time.Time,
) {

	// Update timestamps
	secs := uint32(timeStamp.Unix())
	millis := uint32(timeStamp.Nanosecond()/1_000_000) << 22 // Milliseconds use the 10 MSBs.
	millis |= r.counter
	r.Dec.Base.PathMeta.BaseTS = secs
	r.Dec.Base.PathMeta.HighResTS = millis

	// Increment counter for the next packet. Make sure it always fits in 22 bits.
	r.counter++
	r.counter %= 1 << 22 // Counter is the "tail" of the timestamp, using the 22 LSBs.

	// compute Macs for Flyovers
	var byteBuffer [hummingbird.FlyoverMacBufferSize]byte
	for i, h := range r.Hops {
		// Check if hop is xover (no hop) or non flyover (just best effort)
		if h == nil || h.Flyover == nil {
			continue
		}
		f := h.Flyover
		hf := &r.Dec.HopFields[i]
		hf.ResStartTime = uint16(secs - f.StartTime)

		flyovermac := hummingbird.FlyoverMacWithAkAesBlock(
			r.blocksPerAk[i],
			byteBuffer[:],
			r.DstIA,
			pktLen,
			hf.ResStartTime,
			millis,
		)

		binary.BigEndian.PutUint32(hf.HopField.Mac[:4],
			binary.BigEndian.Uint32(flyovermac[:4])^binary.BigEndian.Uint32(r.scionMacs[i][:4]))
		binary.BigEndian.PutUint16(hf.HopField.Mac[4:],
			binary.BigEndian.Uint16(flyovermac[4:])^binary.BigEndian.Uint16(r.scionMacs[i][4:]))

	}
}

// Expiry returns the earliest time at which one of this reservation's flyovers stops being
// valid. It returns the zero Time if the reservation has no flyovers, i.e. it does not expire
// on its own.
func (r *Reservation) Expiry() time.Time {
	var earliest time.Time
	for _, h := range r.Hops {
		if h == nil || h.Flyover == nil {
			continue
		}
		end := time.Unix(int64(h.Flyover.StartTime)+int64(h.Flyover.Duration), 0)
		if earliest.IsZero() || end.Before(earliest) {
			earliest = end
		}
	}
	return earliest
}

// ReservationModFcn is a options setting function for a reservation.
type ReservationModFcn func(*Reservation) error

// WithDstIA changes the destination IA of the reservation.
func WithDstIA(dstIA addr.IA) ReservationModFcn {
	return func(r *Reservation) error {
		r.DstIA = dstIA
		return nil
	}
}

// WithRawPath can be used to build a Reservation given the RawPath, e.g. in case
// of replying to a received packet.
// Only scion and hummingbird path types are supported.
func WithRawPath(rawPath snet.RawPath, dstIA addr.IA, seq FlyoverSequence) ReservationModFcn {
	return func(r *Reservation) error {
		switch rawPath.PathType {
		case scion.PathType:
			return r.setupReservationWithScion(rawPath.Raw, dstIA, seq)
		case dphum.PathType:
			dec := &dphum.Decoded{}
			if err := dec.DecodeFromBytes(rawPath.Raw); err != nil {
				return err
			}
			return r.setupReservationWithHummDecoded(dec, dstIA, seq)
		default:
			return serrors.New("creating reservation: unsupported path type",
				"type", rawPath.PathType.String(),
			)
		}
	}
}

// WithDataplanePath builds a Reservation from an snet DataplanePath.
// It does not need to deserialize the path from bytes if the path passed is already of
// type Reservation.
func WithDataplanePath(p snet.DataplanePath, dstIA addr.IA, seq FlyoverSequence) ReservationModFcn {
	return func(r *Reservation) error {
		switch p := p.(type) {
		case SCION:
			return r.setupReservationWithScion(p.Raw, dstIA, seq)
		case *Reservation:
			return r.setupReservationWithHummDecoded(p.Dec, dstIA, seq)
		default:
			return serrors.New("creating reservation: unsupported path type",
				"type", fmt.Sprintf("%T", p),
			)
		}
	}
}

// WithReverseFromBidirectional constructs a Reservation given the necessary data from a
// reverse reservation. This is used to create a bidirectional reservation,
// and this option is usually applied at the server side, who receives the reverse reservation
// that was created by the client.
// - serializedReservation is the end to end extension bytes serialized, which represent the hops
// and SCION MACs of the reverse reservation.
// - carrierPath is the path used to send the end to end extension, aka client to server.
// - otherIA is the IA source of carrierPath, aka the client.
func WithReverseFromBidirectional(
	serializedReservation []byte,
	carrierPath snet.RawPath,
	otherIA addr.IA,
) ReservationModFcn {
	return func(r *Reservation) error {
		// 1. Deserialize the return path
		originalPath := carrierPath
		if originalPath.PathType != dphumm.PathType {
			return serrors.New("bidirectional reservations supported only on hummingbird paths",
				"type", originalPath.PathType.String())
		}
		var dec dphumm.Decoded
		if err := dec.DecodeFromBytes(originalPath.Raw); err != nil {
			return serrors.Wrap("bidirectional reservation, decoding humm. path", err)
		}
		// Reverse in place.
		if _, err := dec.Reverse(); err != nil {
			return serrors.Wrap("cannot reverse hummingbird path", err)
		}

		// 2. Deserialize the reservation.
		if err := r.Deserialize(serializedReservation); err != nil {
			return serrors.Wrap("cannot deserialize reverse reservation state", err)
		}
		if len(r.Hops) != len(dec.HopFields) {
			return serrors.New("reverse reservation state does not match reversed dataplane path",
				"reservation_hops", len(r.Hops),
				"hop_fields", len(dec.HopFields),
			)
		}

		// 3. Rebind the reversed dataplane path onto the serialized reverse reservation state.
		r.Dec = &dec
		r.DstIA = otherIA
		r.blocksPerAk = make([]cipher.Block, len(r.Hops))
		for i, hop := range r.Hops {
			if hop == nil {
				continue
			}
			if err := r.SetHopAndFlyover(uint8(i), hop); err != nil {
				return serrors.Wrap("cannot bind reverse reservation hop to dataplane path", err,
					"index", i)
			}
		}

		return nil
	}
}

func (r *Reservation) setScionPath(dec *scion.Decoded) error {
	r.Dec = &hummingbird.Decoded{}
	r.Dec.ConvertFromScionDecoded(dec)

	// Clone the MAC fields.
	r.scionMacs = make([][6]byte, len(dec.HopFields))
	for i, hf := range dec.HopFields {
		r.scionMacs[i] = hf.Mac
	}

	return nil
}

// cloneAggregatedMACsFromHummDecoded clones the aggregated MAC fields into the independent storage,
// so that they are used as SCION MACs.
// Note that if the aggregated MAC fields contained already the flyover MACs in them, they will
// be not be de-aggregated.
func (r *Reservation) cloneAggregatedMACsFromHummDecoded() {
	r.scionMacs = make([][dppath.MacLen]byte, len(r.Dec.HopFields))
	for i, hf := range r.Dec.HopFields {
		r.scionMacs[i] = hf.HopField.Mac
	}
}

func (r *Reservation) SerializedLen() int {
	return lenOfSerializedHops(r.Hops) + dppath.MacLen*len(r.scionMacs)
}

func (r *Reservation) Serialize(buff []byte) error {
	if len(r.scionMacs) != len(r.Hops) {
		return serrors.New("logic error, inconsistent hop and scion mac count",
			"hop count", len(r.Hops),
			"mac count", len(r.scionMacs),
		)
	}
	serializedLen := r.SerializedLen()
	if len(buff) < serializedLen {
		return serrors.New("buffer too small to serialize reservation",
			"expected", serializedLen,
			"actual", len(buff),
		)
	}
	n, err := serializeHops(buff, r.Hops)
	if err != nil {
		return err
	}
	// Copy the original SCION MACs to the serialized buffer.
	buff = buff[n:serializedLen]
	for _, mac := range r.scionMacs {
		copy(buff, mac[:])
		buff = buff[dppath.MacLen:]
	}
	return nil
}

func (r *Reservation) Deserialize(buff []byte) error {
	hops, err := deserializeHops(buff)
	if err != nil {
		return err
	}
	hopsLen := lenOfSerializedHops(hops)
	expectedLen := hopsLen + dppath.MacLen*len(hops)
	if len(buff) != expectedLen {
		return serrors.New("invalid serialized reservation length",
			"expected", expectedLen,
			"actual", len(buff),
		)
	}
	buff = buff[hopsLen:]

	// Copy as many original SCION MACs as hops:
	r.scionMacs = make([][dppath.MacLen]byte, len(hops))
	for i := range len(hops) {
		copy(r.scionMacs[i][:], buff)
		buff = buff[dppath.MacLen:]
	}
	r.Hops = hops
	return nil
}

func (r *Reservation) setupReservationWithScion(
	serializedPath []byte,
	dstIA addr.IA,
	seq FlyoverSequence,
) error {
	var dec scion.Decoded
	if err := dec.DecodeFromBytes(serializedPath); err != nil {
		return err
	}
	if err := r.setScionPath(&dec); err != nil {
		return err
	}
	// hopsFromDP will skip crossovers.
	hopsFromDP, indices, err := scionDataplaneToBaseHops(&dec)
	if err != nil {
		return err
	}

	r.DstIA = dstIA
	// Extend the number of hops to that of the path.
	r.Hops = make([]*Hop, len(r.Dec.HopFields))
	r.blocksPerAk = make([]cipher.Block, len(r.Hops))

	return r.assignFlyovers(seq, hopsFromDP, indices)
}

func (r *Reservation) setupReservationWithHummDecoded(
	hummDec *dphum.Decoded,
	dstIA addr.IA,
	seq FlyoverSequence,
) error {
	r.Dec = &dphum.Decoded{}
	r.Dec = hummDec
	r.cloneAggregatedMACsFromHummDecoded()

	// hopsFromDP will skip crossovers.
	hopsFromDP, indices, err := hummDataplaneToBaseHops(r.Dec)
	if err != nil {
		return err
	}

	r.DstIA = dstIA
	// Extend the number of hops to that of the path.
	r.Hops = make([]*Hop, len(r.Dec.HopFields))
	r.blocksPerAk = make([]cipher.Block, len(r.Hops))

	return r.assignFlyovers(seq, hopsFromDP, indices)
}

func (r *Reservation) assignFlyovers(
	seq FlyoverSequence,
	hopsFromDP []BaseHop,
	hfIndices []uint8,
) error {
	if len(hopsFromDP) != len(seq) || len(hopsFromDP) != len(hfIndices) {
		return serrors.New("inconsistent hummingbird dataplane to flyover mapping",
			"base_hops", len(hopsFromDP),
			"flyover_sequence", len(seq),
			"hop_fields", len(hfIndices))
	}
	for i, hopFromDP := range hopsFromDP {
		hop := seq[i]
		if hop == nil {
			continue
		}

		if hop.BaseHop.Ingress != hopFromDP.Ingress ||
			hop.BaseHop.Egress != hopFromDP.Egress {
			return serrors.New("mismatch hop parameter and data-plane",
				"index", i,
				"hop", hop,
				"dataplane_hop", hopFromDP)
		}
		if err := r.SetHopAndFlyover(hfIndices[i], hop); err != nil {
			return serrors.Wrap("cannot set the flyover for dataplane hop", err,
				"index", i,
				"hop", hop,
				"dataplane hop", hopFromDP)
		}
	}
	return nil
}

func (r *Reservation) SetHopAndFlyover(
	hfIdx uint8,
	hop *Hop,
) error {
	r.Hops[hfIdx] = hop
	if hop.Flyover == nil {
		return nil
	}

	// Find the hop field from its index.
	hf := &r.Dec.HopFields[hfIdx]

	// Validate ingress and egress.
	segIdx := r.Dec.InfIndexForHFIndex(hfIdx)
	in := hf.HopField.ConsIngress
	eg := hf.HopField.ConsEgress
	if !r.Dec.InfoFields[segIdx].ConsDir {
		in, eg = eg, in
	}

	xover := r.Dec.IsCrossOver(hfIdx)
	switch xover {
	case -1:
		if !r.Dec.InfoFields[segIdx+1].ConsDir {
			eg = r.Dec.HopFields[hfIdx+1].HopField.ConsIngress
		} else {
			eg = r.Dec.HopFields[hfIdx+1].HopField.ConsEgress
		}
	case +1:
		if !r.Dec.InfoFields[segIdx-1].ConsDir {
			in = r.Dec.HopFields[hfIdx+1].HopField.ConsEgress
		} else {
			in = r.Dec.HopFields[hfIdx+1].HopField.ConsIngress
		}
	default:
	}
	if in != hop.Ingress || eg != hop.Egress {
		return serrors.New("inconsistent flyover ingress/egress for dataplane",
			"flyover", fmt.Sprintf("in:%d, eg:%d", hop.Ingress, hop.Egress),
			"dataplane", fmt.Sprintf("in:%d, eg:%d", in, eg))
	}

	if !hf.Flyover {
		// Because we are setting a plain hop field as a flyover, it will use two more lines.
		r.Dec.NumLines += 2
		r.Dec.PathMeta.SegLen[segIdx] += 2
		hf.Flyover = true
	}

	hf.Bw = hop.Flyover.Bw
	hf.Duration = hop.Flyover.Duration
	hf.ResID = hop.Flyover.ResID

	// Prepare the AES block with the right Ak.
	block, err := aes.NewCipher(hop.Flyover.Ak[:])
	if err != nil {
		return serrors.Wrap("cannot create AES block", err)
	}
	// Set the AES block to be used by deriveDataPlanePath.
	r.blocksPerAk[hfIdx] = block

	return nil
}

// scionDataplaneToBaseHops maps a decoded SCION dataplane path to its logical ingress/egress
// hop sequence. Segment crossover pairs are collapsed into one logical hop.
func scionDataplaneToBaseHops(dec *scion.Decoded) ([]BaseHop, []uint8, error) {
	return dataplaneToBaseHops(
		dec.NumINF,
		func(i int) dppath.InfoField { return dec.InfoFields[i] },
		[3]int{
			int(dec.PathMeta.SegLen[0]),
			int(dec.PathMeta.SegLen[1]),
			int(dec.PathMeta.SegLen[2]),
		},
		func(i int) dppath.HopField { return dec.HopFields[i] },
	)
}

// hummDataplaneToBaseHops maps a decoded Hummingbird dataplane path to its logical ingress/egress
// hop sequence. Segment crossover pairs are collapsed into one logical hop.
func hummDataplaneToBaseHops(dec *hummingbird.Decoded) ([]BaseHop, []uint8, error) {
	return dataplaneToBaseHops(
		dec.NumINF,
		func(i int) dppath.InfoField { return dec.InfoFields[i] },
		[3]int{
			dec.NumberOfHFsInSegment(0),
			dec.NumberOfHFsInSegment(1),
			dec.NumberOfHFsInSegment(2),
		},
		func(i int) dppath.HopField { return dec.HopFields[i].HopField },
	)
}

// dataplaneToBaseHops converts a path into a BaseHop sequence.
// numINF: number of segments.
// getInf: function to return segment i.
// hfCountPerSegment: number of hop fields, per segment. Not lines, but actual hop field count.
// getHF: function to return hop field i.
// Returns:
// - BaseHop sequence, ingress/egress in the right order, and crossover hops merged.
// - Index sequence (crossover hops not present in this sequence).
func dataplaneToBaseHops(
	numINF int,
	getINF func(i int) dppath.InfoField,
	hfCountPerSegment [3]int, // Number of hops (not lines)
	getHF func(i int) dppath.HopField,
) ([]BaseHop, []uint8, error) {
	if numINF > 3 {
		return nil, nil, serrors.New("inconsistent path", "num_inf", numINF)
	}
	// BaseHop sequence, with capacity for all hops (it might end being less, from crossovers).
	totalHfCount := hfCountPerSegment[0] + hfCountPerSegment[1] + hfCountPerSegment[2]
	baseHops := make([]BaseHop, 0, totalHfCount)
	indices := make([]uint8, 0, totalHfCount)

	hfIdx := 0
	for segIdx := range numINF {
		inf := getINF(segIdx)
		if hfCountPerSegment[segIdx] == 0 {
			return nil, nil, serrors.New("segment with no hops", "seg_idx", segIdx)
		}
		// Check peering consistency.
		if segIdx > 0 && getINF(segIdx-1).Peer != inf.Peer {
			// Peering inconsistent.
			return nil, nil, serrors.New("inconsistent path, joined segments peering disagreement",
				"num_inf", numINF, "seg_idx", segIdx,
				"prev_peer", getINF(segIdx-1).Peer, "curr_peer", inf.Peer)
		}
		// For each hop in this segment.
		for hopInSegment := range hfCountPerSegment[segIdx] {
			hf := getHF(hfIdx)
			in := hf.ConsIngress
			eg := hf.ConsEgress
			if !inf.ConsDir {
				in, eg = eg, in
			}

			// Check for crossovers and shortcuts.
			if segIdx > 0 && hopInSegment == 0 && !inf.Peer {
				// Crossover. Replace the previous egress with the one in this hop field:
				// - If it is a core AS (crossover): Previous egress was zero.
				// - If not core AS (shortcut): Previous egress was the parent-facing interface ID.
				baseHops[len(baseHops)-1].Egress = eg
			} else {
				// Not a crossover. Add the new hop field.
				hop := BaseHop{
					Ingress: in,
					Egress:  eg,
				}
				baseHops = append(baseHops, hop)
				indices = append(indices, uint8(hfIdx))
			}
			hfIdx++
		}
	}

	return baseHops, indices, nil
}

// BaseHop describes a pair of Ingress and Egress interfaces in a specific AS
type BaseHop struct {
	IA      addr.IA
	Ingress uint16
	Egress  uint16
}

type Hop struct {
	BaseHop
	Flyover *FlyoverData // nil if this hop is not reserved (just best effort)
}

type FlyoverData struct {
	ResID     uint32   // Unique per AS.
	Ak        [16]byte // Authentication key.
	Bw        uint16
	StartTime uint32 // Unix timestamp for the start of the reservation.
	Duration  uint16 // Duration of the reservation in seconds.
}

const HopNoFlyoverLen = 12 // bytes
// ResID = 22 bits
// Bw = 10 bits
// Ak = 16 bytes
// StartTime = 4 bytes
// Duration = 4 bytes
const FlyoverLen = 4 + 16 + 4 + 4
const HopWithFlyoverLen = HopNoFlyoverLen + FlyoverLen

// Len returns the length of the hop in bytes.
func (h Hop) Len() int {

	l := HopNoFlyoverLen
	if h.Flyover != nil {
		l += FlyoverLen
	}
	return l
}

func (h Hop) Serialize(buff []byte) (int, error) {
	l := h.Len()
	if len(buff) < l {
		return 0, serrors.New("buffer is too small",
			"expected", l,
			"got", len(buff))
	}
	buff = buff[:0]
	buff = binary.BigEndian.AppendUint64(buff, uint64(h.IA))
	buff = binary.BigEndian.AppendUint16(buff, h.Ingress)
	buff = binary.BigEndian.AppendUint16(buff, h.Egress)

	if h.Flyover != nil {
		buff = binary.BigEndian.AppendUint32(buff, h.Flyover.ResID<<10|uint32(h.Flyover.Bw))
		buff = append(buff, h.Flyover.Ak[:]...)
		buff = binary.BigEndian.AppendUint32(buff, h.Flyover.StartTime)
		buff = binary.BigEndian.AppendUint16(buff, h.Flyover.Duration)
	}
	return l, nil
}

func (h *Hop) Deserialize(buff []byte, hasFlyover bool) error {
	expected := HopNoFlyoverLen
	if hasFlyover {
		expected += FlyoverLen
	}
	if len(buff) < expected {
		return serrors.New("buffer is too small",
			"expected", HopNoFlyoverLen+FlyoverLen,
			"got", len(buff))

	}
	h.IA = addr.IA(binary.BigEndian.Uint64(buff))
	buff = buff[8:]
	h.Ingress = binary.BigEndian.Uint16(buff)
	buff = buff[2:]
	h.Egress = binary.BigEndian.Uint16(buff)
	buff = buff[2:]

	if hasFlyover {
		h.Flyover = &FlyoverData{}
		resIdBw := binary.BigEndian.Uint32(buff)
		buff = buff[4:]
		h.Flyover.ResID = resIdBw >> 10
		h.Flyover.Bw = uint16(resIdBw) & 0x000003FF // lowest 10 bits
		copy(h.Flyover.Ak[:], buff)
		buff = buff[16:]
		h.Flyover.StartTime = binary.BigEndian.Uint32(buff)
		buff = buff[4:]
		h.Flyover.Duration = binary.BigEndian.Uint16(buff)
		buff = buff[2:]
	}
	return nil
}

func lenOfSerializedHops(hops []*Hop) int {
	l := 1
	bitsetBytes := backingBytesForHopBitset(len(hops))
	l += bitsetBytes // bytes to hold the hop existence flags.
	l += bitsetBytes // bytes to hold the flyover flags.
	for _, h := range hops {
		if h == nil {
			continue
		}
		l += h.Len()
	}
	return l
}

// serializeHops serializes up to 255 hops.
// The structure of the buffer ends up as:
// - Hop count, 1 byte.
// - Hop existence flag bitset, for all hops; (hop count+7) / 8
// - Flyover flag bitset, for all hops; (hop count+7) / 8
// - Sequence of non-nil Hops.
func serializeHops(buff []byte, hops []*Hop) (int, error) {
	if len(hops) > 255 {
		return 0, serrors.New("cannot serialize more than 255 hops", "requested", len(hops))
	}
	// Check size.
	expectedSize := lenOfSerializedHops(hops)
	if len(buff) < expectedSize {
		return 0, serrors.New("buffer is too small",
			"expected", expectedSize,
			"got", len(buff))
	}

	// Serialize.
	buff[0] = byte(len(hops))
	buff = buff[1:]
	bitsetBytes := backingBytesForHopBitset(len(hops))

	existsFlags := newHopBitset(buff[:bitsetBytes], len(hops))
	existsFlags.Clear()
	buff = buff[bitsetBytes:]

	flyoverFlags := newHopBitset(buff[:bitsetBytes], len(hops))
	flyoverFlags.Clear()
	buff = buff[bitsetBytes:]

	var err error
	var n int
	for i, h := range hops {
		if h == nil {
			continue
		}
		existsFlags.Set(i, true)
		if h.Flyover != nil {
			flyoverFlags.Set(i, true)
		}
		n, err = h.Serialize(buff)
		if err != nil {
			return n, serrors.Wrap("serializing hop field", err, "i", i)
		}
		buff = buff[n:]
	}
	return expectedSize, nil
}

func deserializeHops(buff []byte) ([]*Hop, error) {
	if len(buff) == 0 {
		return nil, nil
	}
	N := int(buff[0])

	bitsetBytes := backingBytesForHopBitset(N)
	headerLen := 1 + 2*bitsetBytes
	if len(buff) < headerLen {
		return nil, serrors.New("buffer is too small",
			"expected", headerLen,
			"got", len(buff))
	}
	existsFlags := newHopBitset(buff[1:1+bitsetBytes], N)
	flyoverFlags := newHopBitset(buff[1+bitsetBytes:headerLen], N)
	hopData := buff[headerLen:]
	expectedPayloadLen := 0
	for i := range N {
		exists := existsFlags.Get(i)
		hasFlyover := flyoverFlags.Get(i)
		if !exists {
			if hasFlyover {
				return nil, serrors.New("deserialize hops: non-existent hop has flyover",
					"at_index", i)
			}
			continue
		}
		if hasFlyover {
			expectedPayloadLen += HopWithFlyoverLen
		} else {
			expectedPayloadLen += HopNoFlyoverLen
		}
	}
	expectedLen := headerLen + expectedPayloadLen

	if len(buff) < expectedLen {
		return nil, serrors.New("buffer is too small",
			"expected", expectedLen,
			"got", len(buff))
	}

	hops := make([]*Hop, N)
	for i := range N {
		if !existsFlags.Get(i) {
			continue
		}
		hops[i] = &Hop{}
		hasFlyover := flyoverFlags.Get(i)
		err := hops[i].Deserialize(hopData, hasFlyover)
		if err != nil {
			return nil, serrors.Wrap("deserialize hops", err)
		}
		if hasFlyover {
			hopData = hopData[HopWithFlyoverLen:]
		} else {
			hopData = hopData[HopNoFlyoverLen:]
		}
	}
	return hops, nil
}

// FlyoverSequence represents a sequence of hops. These hops may contain flyovers.
type FlyoverSequence []*Hop

// InterfacesToBaseHops maps path metadata interfaces to per-AS ingress/egress hop tuples.
// Crossovers are removed directly by the metadata setting logic at pathSolution.Path()
// in package private/path/combinator .
func InterfacesToBaseHops(ifaces []snet.PathInterface) []BaseHop {
	if len(ifaces) == 0 {
		return nil
	}
	baseHops := make([]BaseHop, 0, len(ifaces)/2+1)
	baseHops = append(baseHops, BaseHop{
		IA:      ifaces[0].IA,
		Ingress: 0,
		Egress:  uint16(ifaces[0].ID),
	})

	for i := 1; i < len(ifaces); i += 2 {
		egress := uint16(0)
		if i+1 < len(ifaces) {
			egress = uint16(ifaces[i+1].ID)
		}
		baseHops = append(baseHops, BaseHop{
			IA:      ifaces[i].IA,
			Ingress: uint16(ifaces[i].ID),
			Egress:  egress,
		})
	}
	return baseHops
}

type hopBitset struct {
	nBits int
	buf   []byte
}

func backingBytesForHopBitset(nBits int) int {
	return (nBits + 7) / 8
}

func newHopBitset(backing []byte, nBits int) hopBitset {
	nBytes := backingBytesForHopBitset(nBits)
	b := backing[:nBytes]
	return hopBitset{
		nBits: nBits,
		buf:   b,
	}
}

func (b hopBitset) Clear() {
	clear(b.buf) // all bits to zero
}

func (b hopBitset) Set(i int, value bool) {
	byteIdx := i / 8
	bitIdx := uint(i % 8)

	mask := byte(1 << bitIdx) // LSB-first within each byte
	if value {
		b.buf[byteIdx] |= mask
	} else {
		b.buf[byteIdx] &^= mask
	}
}

func (b hopBitset) Get(i int) bool {
	byteIdx := i / 8
	bitIdx := uint(i % 8)
	return b.buf[byteIdx]&(1<<bitIdx) != 0
}

func (b hopBitset) TotalBits() int {
	return b.nBits
}

func (b hopBitset) CountOnes() int {
	count := 0
	for i := range b.nBits {
		if b.Get(i) {
			count++
		}
	}
	return count
}

func (b hopBitset) CountZeroes() int {
	return b.TotalBits() - b.CountOnes()
}

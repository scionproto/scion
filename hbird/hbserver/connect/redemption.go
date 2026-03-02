package connect

import (
	"context"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	hb "github.com/scionproto/scion/hbird"
	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/log"
	hbirdv1 "github.com/scionproto/scion/pkg/proto/hbird/v1"
	"github.com/scionproto/scion/private/topology"
)

const (
	// Wire format constants
	BW_BITS          = 10
	BW_EXP_BITS      = 5
	RESID_BITS       = 22
	MAX_DURATION_SEC = math.MaxUint16
)

type HBirdServer struct {
	Topo      *topology.Loader
	HbService *HummingbirdKeyDerivationService
	Icm       *hb.IntervalColorMap
}

func (s *HBirdServer) Status(_ context.Context, _ *connect.Request[emptypb.Empty]) (
	*connect.Response[hbirdv1.StatusResponse],
	error) {
	res := &hbirdv1.StatusResponse{Version: 0}
	return connect.NewResponse(res), nil
}

func (s *HBirdServer) Redeem(
	ctx context.Context,
	req *connect.Request[hbirdv1.RedemptionRequests],
) (
	*connect.Response[hbirdv1.RedemptionResponses],
	error) {

	res, err := s.redeem(ctx, req)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(res), nil
}

func (s *HBirdServer) redeem(_ context.Context,
	req *connect.Request[hbirdv1.RedemptionRequests],
) (*hbirdv1.RedemptionResponses,
	error) {

	log.Debug("Redeem request message:", req.Msg)
	isdAs := s.Topo.IA()
	clientKey := req.Msg.ClientKey

	response := &hbirdv1.RedemptionResponses{
		Reservation: []*hbirdv1.Reservation{},
	}
	for _, redReq := range req.Msg.Redemption {
		dur, err := time.ParseDuration(fmt.Sprintf("%ds", redReq.RedInfo.Duration))
		if err != nil {
			return nil, err
		}

		resInfo := NewResInfo(
			isdAs,
			uint16(redReq.RedInfo.Ingress),
			uint16(redReq.RedInfo.Egress),
			FromKbps(uint64(redReq.RedInfo.Bw)),
			time.Unix(int64(redReq.RedInfo.StartTime), 0),
			dur,
		)

		err = resInfo.Check()
		err = nil // XXX: skipping check for now
		if err != nil {
			return nil, err
		}

		low := int(redReq.RedInfo.StartTime) % s.Icm.NUnitIntervals
		high := int(dur.Seconds())
		resID, err := s.Icm.AssignColor(low, high)
		if err != nil {
			return nil, err
		}
		reserving, err := resInfo.WithResID(resID)
		if err != nil {
			return nil, err
		}

		reserved, err := s.HbService.AssignAuthenticationKey(reserving)
		if err != nil {
			return nil, err
		}
		log.Debug("redeem processing", "clientKey:",
			base64.StdEncoding.EncodeToString(clientKey), "reserved.AuthenticationKey:",
			base64.StdEncoding.EncodeToString(reserved.AuthenticationKey))
		encryptedAk, err := ClientEncrypt(clientKey, reserved.AuthenticationKey)
		if err != nil {
			return nil, fmt.Errorf("invalid client info")
		}
		res := hbirdv1.Reservation{
			Ia:      uint64(reserved.ResInfo.IA),
			ResId:   reserved.ResInfo.ResID,
			AuthKey: encryptedAk,
		}
		log.Debug("redeem reservation", "Ia:", res.Ia, "ResId:", res.ResId,
			"AuthKey", base64.StdEncoding.EncodeToString(res.AuthKey))
		response.Reservation = append(response.Reservation, &res)
	}
	return response, nil
}

func ClientEncrypt(clientPublicKey []byte, payload []byte) (cipher []byte, err error) {
	pubKey, err := x509.ParsePKCS1PublicKey(clientPublicKey)
	if err != nil {
		return nil, err
	}
	cipher, err = rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, payload, nil)
	if err != nil {
		return nil, err
	}
	return cipher, nil
}

// Bandwidth in kbps
type Bandwidth struct {
	kbps uint64
}

// FromKbps
func FromKbps(kbps uint64) Bandwidth {
	return Bandwidth{kbps: kbps}
}

// AsKbps
func (b Bandwidth) AsKbps() uint64 {
	return b.kbps
}

// ToWireFormat convert bandwidth in kbps to wire format encoding
func (b Bandwidth) ToWireFormat() (uint16, error) {
	significandBits := BW_BITS - BW_EXP_BITS
	significandValues := uint64(1 << significandBits)
	// Special case: exponent = 0
	if b.kbps < significandValues {
		return uint16(b.kbps), nil
	}

	// exponent offset by 1 to account for above case
	exponent := uint(bits.Len64(b.kbps)) - uint(significandBits)
	if exponent >= (1 << BW_EXP_BITS) {
		return 0, fmt.Errorf("bandwidth too large, cannot convert to wire format: %v", b.kbps)
	}

	// compute significand
	// shift right by (exponent - 1), then subtract the implicit prepended '1'
	significand := (b.kbps >> (exponent - 1)) - significandValues

	return (uint16(exponent) << significandBits) | uint16(significand), nil
}

// FromWireFormat decodes wire format to integer bandwidth in kbps
func FromWireFormat(wireFormat uint16) (Bandwidth, error) {
	significandBits := BW_BITS - BW_EXP_BITS
	// Check total bit-size
	if (16 - bits.LeadingZeros16(wireFormat)) > BW_BITS {
		return Bandwidth{}, errors.New("bandwidth could not be converted, value too large")
	}

	exponent := wireFormat >> significandBits
	significand := wireFormat & ((1 << significandBits) - 1)
	if exponent == 0 {
		return Bandwidth{kbps: uint64(significand)}, nil
	}

	return Bandwidth{
		kbps: (uint64(significand) + (1 << significandBits)) << (exponent - 1),
	}, nil
}

// ResInfo
type ResInfo struct {
	IA               addr.IA
	IngressInterface uint16
	EgressInterface  uint16
	ResID            uint32
	Bandwidth        Bandwidth
	StartTime        time.Time
	Duration         time.Duration
}

// NewResInfo
func NewResInfo(
	isd_as addr.IA,
	ingress, egress uint16,
	bw Bandwidth,
	start time.Time,
	duration time.Duration,
) ResInfo {
	return ResInfo{
		IA:               isd_as,
		IngressInterface: ingress,
		EgressInterface:  egress,
		Bandwidth:        bw,
		StartTime:        start,
		Duration:         duration,
	}
}

// WithResID checks that the given resID fits in RESID_BITS bits
func (r ResInfo) WithResID(resID uint32) (ResInfo, error) {
	// We check that no bits above RESID_BITS are set.
	masked := ^(uint32(1)<<(RESID_BITS) - 1)
	if resID&masked != 0 {
		return ResInfo{}, fmt.Errorf("the assigned ResId is too long: %d", resID)
	}
	r.ResID = resID
	return r, nil
}

func (r ResInfo) Check() error {
	expired := time.Unix(100_000, 0).After(r.StartTime.Add(r.Duration))
	identity, _ := addr.ParseIA("1-0:0:0110")
	validIA := r.IA == identity
	maxFreeBW := uint64(2000)
	validBW := r.Bandwidth.AsKbps() < maxFreeBW
	currIF := uint16(2)
	validIF := r.EgressInterface == currIF || r.IngressInterface == currIF
	if expired || !validIA || !validBW || !validIF {
		fmt.Println("expired, !validIA, !validBW, !validIF",
			expired, !validIA, !validBW, !validIF)
		return errors.New("Invalid ResInfo")
	}
	return nil
}

// TimeBandwidthProductKb is the product of bandwidth and duration in kb.
func (r ResInfo) TimeBandwidthProductKb() uint64 {
	seconds := uint64(r.Duration.Seconds())
	return r.Bandwidth.AsKbps() * seconds
}

// CompleteReservation
type CompleteReservation struct {
	ResInfo           ResInfo
	AuthenticationKey []byte
}

// HummingbirdKeyDerivationService holds the AES master key
// and can encrypt a single 16-byte block to produce the auth key.
type HummingbirdKeyDerivationService struct {
	masterKey [16]byte
}

// NewHummingbirdKeyDerivationService
func NewHummingbirdKeyDerivationService(key [16]byte) *HummingbirdKeyDerivationService {
	return &HummingbirdKeyDerivationService{masterKey: key}
}

// AssignAuthenticationKey runs single-block AES-128 encryption
func (h *HummingbirdKeyDerivationService) AssignAuthenticationKey(
	r ResInfo,
) (*CompleteReservation, error) {
	block, err := ComputeAuthenticationKey(r, h.masterKey)
	if err != nil {
		return nil, err
	}

	// Build final reservation.
	return &CompleteReservation{
		ResInfo:           r,
		AuthenticationKey: block[:],
	}, nil
}

func ComputeAuthenticationKey(r ResInfo, masterKey [16]byte) (*[16]byte, error) {
	// Create AES cipher.
	blockCipher, err := aes.NewCipher(masterKey[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-128 cipher: %w", err)
	}
	// Combine res_id and bandwidth bits:
	bwVal, err := r.Bandwidth.ToWireFormat()
	if err != nil {
		return nil, err
	}
	resIDConcatBW := (r.ResID << BW_BITS) | uint32(bwVal)

	// Build the 16-byte block.
	// Indices:
	//   [0..2] = ingress (u16 big-endian)
	//   [2..4] = egress (u16 big-endian)
	//   [4..8] = resIDConcatBW (u32 big-endian)
	//   [8..12] = start_time (u32 big-endian)
	//   [12..14] = duration (u16 big-endian)
	var block [16]byte

	binary.BigEndian.PutUint16(block[0:2], r.IngressInterface)
	binary.BigEndian.PutUint16(block[2:4], r.EgressInterface)
	binary.BigEndian.PutUint32(block[4:8], resIDConcatBW)

	// StartTime as 32-bit Unix time
	unixStart := uint32(r.StartTime.Unix())
	binary.BigEndian.PutUint32(block[8:12], unixStart)

	// Duration in seconds as a 16-bit
	durSeconds := uint16(r.Duration.Seconds())
	binary.BigEndian.PutUint16(block[12:14], durSeconds)
	// [14..16] is zero

	// Encrypt the block in-place
	blockCipher.Encrypt(block[:], block[:])
	return &block, nil
}

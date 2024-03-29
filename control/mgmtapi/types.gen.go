// Package mgmtapi provides primitives to interact with the openapi HTTP API.
//
// Code generated by unknown module path version unknown version DO NOT EDIT.
package mgmtapi

import (
	"time"
)

// Defines values for BeaconUsage.
const (
	CoreRegistration BeaconUsage = "core_registration"
	DownRegistration BeaconUsage = "down_registration"
	Propagation      BeaconUsage = "propagation"
	UpRegistration   BeaconUsage = "up_registration"
)

// Defines values for LogLevelLevel.
const (
	Debug LogLevelLevel = "debug"
	Error LogLevelLevel = "error"
	Info  LogLevelLevel = "info"
)

// Defines values for Status.
const (
	Degraded Status = "degraded"
	Failing  Status = "failing"
	Passing  Status = "passing"
)

// Defines values for GetBeaconsParamsSort.
const (
	Expiration       GetBeaconsParamsSort = "expiration"
	IngressInterface GetBeaconsParamsSort = "ingress_interface"
	LastUpdated      GetBeaconsParamsSort = "last_updated"
	StartIsdAs       GetBeaconsParamsSort = "start_isd_as"
	Timestamp        GetBeaconsParamsSort = "timestamp"
)

// Beacon defines model for Beacon.
type Beacon struct {
	Expiration time.Time `json:"expiration"`
	Hops       []Hop     `json:"hops"`
	Id         SegmentID `json:"id"`

	// IngressInterface Ingress interface of the beacon.
	IngressInterface int          `json:"ingress_interface"`
	LastUpdated      time.Time    `json:"last_updated"`
	Timestamp        time.Time    `json:"timestamp"`
	Usages           BeaconUsages `json:"usages"`
}

// BeaconGetResponseJson defines model for BeaconGetResponseJson.
type BeaconGetResponseJson struct {
	Beacon Beacon `json:"beacon"`
}

// BeaconUsage defines model for BeaconUsage.
type BeaconUsage string

// BeaconUsages defines model for BeaconUsages.
type BeaconUsages = []BeaconUsage

// CA defines model for CA.
type CA struct {
	CertValidity Validity     `json:"cert_validity"`
	Policy       Policy       `json:"policy"`
	Subject      Subject      `json:"subject"`
	SubjectKeyId SubjectKeyID `json:"subject_key_id"`
}

// Certificate defines model for Certificate.
type Certificate struct {
	DistinguishedName string       `json:"distinguished_name"`
	IsdAs             IsdAs        `json:"isd_as"`
	SubjectKeyAlgo    string       `json:"subject_key_algo"`
	SubjectKeyId      SubjectKeyID `json:"subject_key_id"`
	Validity          Validity     `json:"validity"`
}

// Chain defines model for Chain.
type Chain struct {
	Issuer  Certificate `json:"issuer"`
	Subject Certificate `json:"subject"`
}

// ChainBrief defines model for ChainBrief.
type ChainBrief struct {
	Id       ChainID  `json:"id"`
	Issuer   IsdAs    `json:"issuer"`
	Subject  IsdAs    `json:"subject"`
	Validity Validity `json:"validity"`
}

// ChainID defines model for ChainID.
type ChainID = string

// Check defines model for Check.
type Check struct {
	Data CheckData `json:"data"`

	// Detail Additional information.
	Detail *string `json:"detail,omitempty"`

	// Name Name of health check.
	Name string `json:"name"`

	// Reason Reason for check failure.
	Reason *string `json:"reason,omitempty"`
	Status Status  `json:"status"`
}

// CheckData defines model for CheckData.
type CheckData map[string]interface{}

// Health defines model for Health.
type Health struct {
	// Checks List of health checks.
	Checks []Check `json:"checks"`
	Status Status  `json:"status"`
}

// HealthResponse defines model for HealthResponse.
type HealthResponse struct {
	Health Health `json:"health"`
}

// Hop defines model for Hop.
type Hop struct {
	Interface int   `json:"interface"`
	IsdAs     IsdAs `json:"isd_as"`
}

// IsdAs defines model for IsdAs.
type IsdAs = string

// LogLevel defines model for LogLevel.
type LogLevel struct {
	// Level Logging level
	Level LogLevelLevel `json:"level"`
}

// LogLevelLevel Logging level
type LogLevelLevel string

// Policy defines model for Policy.
type Policy struct {
	ChainLifetime string `json:"chain_lifetime"`
}

// Problem defines model for Problem.
type Problem struct {
	// Detail A human readable explanation specific to this occurrence of the problem that is helpful to locate the problem and give advice on how to proceed. Written in English and readable for engineers, usually not suited for non technical stakeholders and not localized.
	Detail *string `json:"detail,omitempty"`

	// Instance A URI reference that identifies the specific occurrence of the problem, e.g. by adding a fragment identifier or sub-path to the problem type. May be used to locate the root of this problem in the source code.
	Instance *string `json:"instance,omitempty"`

	// Status The HTTP status code generated by the origin server for this occurrence of the problem.
	Status int `json:"status"`

	// Title A short summary of the problem type. Written in English and readable for engineers, usually not suited for non technical stakeholders and not localized.
	Title string `json:"title"`

	// Type A URI reference that uniquely identifies the problem type only in the context of the provided API. Opposed to the specification in RFC-7807, it is neither recommended to be dereferencable and point to a human-readable documentation nor globally unique for the problem type.
	Type *string `json:"type,omitempty"`
}

// Segment defines model for Segment.
type Segment struct {
	Expiration  time.Time `json:"expiration"`
	Hops        []Hop     `json:"hops"`
	Id          SegmentID `json:"id"`
	LastUpdated time.Time `json:"last_updated"`
	Timestamp   time.Time `json:"timestamp"`
}

// SegmentBrief defines model for SegmentBrief.
type SegmentBrief struct {
	EndIsdAs IsdAs     `json:"end_isd_as"`
	Id       SegmentID `json:"id"`

	// Length Length of the segment.
	Length     int   `json:"length"`
	StartIsdAs IsdAs `json:"start_isd_as"`
}

// SegmentID defines model for SegmentID.
type SegmentID = string

// Signer defines model for Signer.
type Signer struct {
	AsCertificate Certificate `json:"as_certificate"`

	// Expiration Signer expiration imposed by chain and TRC validity.
	Expiration time.Time `json:"expiration"`
	TrcId      TRCID     `json:"trc_id"`

	// TrcInGracePeriod TRC used as trust root is in grace period, and the latest TRC cannot
	// be used as trust root.
	TrcInGracePeriod bool `json:"trc_in_grace_period"`
}

// StandardError defines model for StandardError.
type StandardError struct {
	// Error Error message
	Error string `json:"error"`
}

// Status defines model for Status.
type Status string

// Subject defines model for Subject.
type Subject struct {
	IsdAs IsdAs `json:"isd_as"`
}

// SubjectKeyID defines model for SubjectKeyID.
type SubjectKeyID = string

// TRC defines model for TRC.
type TRC struct {
	AuthoritativeAses []IsdAs  `json:"authoritative_ases"`
	CoreAses          []IsdAs  `json:"core_ases"`
	Description       string   `json:"description"`
	Id                TRCID    `json:"id"`
	Validity          Validity `json:"validity"`
}

// TRCBrief defines model for TRCBrief.
type TRCBrief struct {
	Id TRCID `json:"id"`
}

// TRCID defines model for TRCID.
type TRCID struct {
	BaseNumber   int `json:"base_number"`
	Isd          int `json:"isd"`
	SerialNumber int `json:"serial_number"`
}

// Topology defines model for Topology.
type Topology map[string]interface{}

// Validity defines model for Validity.
type Validity struct {
	NotAfter  time.Time `json:"not_after"`
	NotBefore time.Time `json:"not_before"`
}

// BadRequest defines model for BadRequest.
type BadRequest = StandardError

// Internal defines model for Internal.
type Internal = StandardError

// GetBeaconsParams defines parameters for GetBeacons.
type GetBeaconsParams struct {
	// StartIsdAs Start ISD-AS of beacons. The address can include wildcards (0) both for the ISD and AS identifier.
	StartIsdAs *IsdAs `form:"start_isd_as,omitempty" json:"start_isd_as,omitempty"`

	// Usages Minimum allowed usages of the returned beacons. Only beacons that are allowed in all the usages in the list will be returned.
	Usages *BeaconUsages `form:"usages,omitempty" json:"usages,omitempty"`

	// IngressInterface Ingress interface id.
	IngressInterface *int `form:"ingress_interface,omitempty" json:"ingress_interface,omitempty"`

	// ValidAt Timestamp at which returned beacons are valid. If unset then the current datetime is used. This only has an effect if `all=false`.
	ValidAt *time.Time `form:"valid_at,omitempty" json:"valid_at,omitempty"`

	// All Include beacons regardless of expiration and creation time.
	All *bool `form:"all,omitempty" json:"all,omitempty"`

	// Desc Whether to reverse the sort order (ascending by default).
	Desc *bool `form:"desc,omitempty" json:"desc,omitempty"`

	// Sort Attribute by which results are sorted. The value `start_isd_as` refers to the ISD-AS identifier of the first hop.
	Sort *GetBeaconsParamsSort `form:"sort,omitempty" json:"sort,omitempty"`
}

// GetBeaconsParamsSort defines parameters for GetBeacons.
type GetBeaconsParamsSort string

// GetCertificatesParams defines parameters for GetCertificates.
type GetCertificatesParams struct {
	IsdAs   *IsdAs     `form:"isd_as,omitempty" json:"isd_as,omitempty"`
	ValidAt *time.Time `form:"valid_at,omitempty" json:"valid_at,omitempty"`
	All     *bool      `form:"all,omitempty" json:"all,omitempty"`
}

// GetSegmentsParams defines parameters for GetSegments.
type GetSegmentsParams struct {
	// StartIsdAs Start ISD-AS of segment.
	StartIsdAs *IsdAs `form:"start_isd_as,omitempty" json:"start_isd_as,omitempty"`

	// EndIsdAs Terminal AS of segment.
	EndIsdAs *IsdAs `form:"end_isd_as,omitempty" json:"end_isd_as,omitempty"`
}

// GetTrcsParams defines parameters for GetTrcs.
type GetTrcsParams struct {
	Isd *[]int `form:"isd,omitempty" json:"isd,omitempty"`
	All *bool  `form:"all,omitempty" json:"all,omitempty"`
}

// SetLogLevelJSONRequestBody defines body for SetLogLevel for application/json ContentType.
type SetLogLevelJSONRequestBody = LogLevel

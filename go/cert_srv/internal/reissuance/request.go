// Copyright 2019 Anapaya Systems
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

package reissuance

import (
	"bytes"
	"encoding/json"
	"unicode/utf8"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/lib/util"
)

var (
	// ErrMissingProtectedField indicates a missing protected field.
	ErrMissingProtectedField = serrors.New("missing protected field")
	// ErrNotUTF8 indicates an invalid encoding.
	ErrNotUTF8 = serrors.New("not utf-8 encoded")
)

// BaseRequest is the base information of the reissuance request.
type BaseRequest struct {
	cert.Base
	Issuer      addr.IA       `json:"issuer"`
	RequestTime util.UnixTime `json:"request_time"`
}

// Request is the reissuance request.
type Request struct {
	BaseRequest
	POPs []POP
}

// POP is a proof of possession.
type POP struct {
	Encoded          EncodedBaseRequest `json:"payload"`
	EncodedProtected EncodedProtected   `json:"protected"`
	Signature        []byte             `json:"signature"`
}

// SigInput computes the signature input according to rfc7517 (see:
// https://tools.ietf.org/html/rfc7515#section-5.1)
func (p POP) SigInput() []byte {
	return scrypto.JWSignatureInput([]byte(p.EncodedProtected), []byte(p.Encoded))
}

// EncodedBaseRequest is the base64url encoded marshaled base request.
type EncodedBaseRequest []byte

// EncodeBaseRequest encodes the base request.
func EncodeBaseRequest(r *BaseRequest) (EncodedBaseRequest, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	return []byte(scrypto.Base64.EncodeToString(b)), nil
}

// Decode decodes and returns the request.
func (e EncodedBaseRequest) Decode() (BaseRequest, error) {
	b, err := scrypto.Base64.DecodeString(string(e))
	if err != nil {
		return BaseRequest{}, err
	}
	var request BaseRequest
	if err := json.Unmarshal(b, &request); err != nil {
		return BaseRequest{}, err
	}
	return request, nil
}

// SignedRequest is a signed reissuance request.
type SignedRequest struct {
	Encoded          EncodedRequest   `json:"payload"`
	EncodedProtected EncodedProtected `json:"protected"`
	Signature        []byte           `json:"signature"`
}

// SigInput computes the signature input according to rfc7517 (see:
// https://tools.ietf.org/html/rfc7515#section-5.1)
func (s SignedRequest) SigInput() []byte {
	return scrypto.JWSignatureInput([]byte(s.EncodedProtected), []byte(s.Encoded))
}

// ParseSignedRequest parses the raw signed request.
func ParseSignedRequest(raw []byte) (SignedRequest, error) {
	var signed SignedRequest
	if err := json.Unmarshal(raw, &signed); err != nil {
		return SignedRequest{}, err
	}
	return signed, nil
}

// EncodedRequest is the base64Url encoded marshaled reissuance request.
type EncodedRequest string

// EncodeRequest encodes the reissuance request.
func EncodeRequest(r *Request) (EncodedRequest, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return EncodedRequest(scrypto.Base64.EncodeToString(b)), nil
}

// Decode decodes and returns the request.
func (e EncodedRequest) Decode() (Request, error) {
	b, err := scrypto.Base64.DecodeString(string(e))
	if err != nil {
		return Request{}, err
	}
	var request Request
	if err := json.Unmarshal(b, &request); err != nil {
		return Request{}, err
	}
	return request, nil
}

// EncodedProtected is the base64url encoded utf-8 metadata.
type EncodedProtected string

// EncodeProtected encodes the protected header.
func EncodeProtected(p Protected) (EncodedProtected, error) {
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return EncodedProtected(scrypto.Base64.EncodeToString(b)), nil
}

// Decode decodes and returns the protected header.
func (e EncodedProtected) Decode() (Protected, error) {
	b, err := scrypto.Base64.DecodeString(string(e))
	if err != nil {
		return Protected{}, err
	}
	if !utf8.Valid(b) {
		return Protected{}, ErrNotUTF8
	}
	var meta Protected
	if err := json.Unmarshal(b, &meta); err != nil {
		return Protected{}, err
	}
	return meta, nil
}

// Protected contains the signature metadata.
type Protected struct {
	Algorithm  string             `json:"alg"`
	KeyType    cert.KeyType       `json:"key_type"`
	KeyVersion scrypto.KeyVersion `json:"key_version"`
	Crit       CritRequest        `json:"crit"`
}

// UnmarshalJSON checks that all fields are set.
func (p *Protected) UnmarshalJSON(b []byte) error {
	var alias protectedAlias
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&alias); err != nil {
		return err
	}
	if err := alias.checkAllSet(); err != nil {
		return err
	}
	*p = Protected{
		Algorithm:  *alias.Algorithm,
		KeyType:    *alias.KeyType,
		KeyVersion: *alias.KeyVersion,
		Crit:       *alias.Crit,
	}
	return nil
}

type protectedAlias struct {
	Algorithm  *string             `json:"alg"`
	Crit       *CritRequest        `json:"crit"`
	KeyType    *cert.KeyType       `json:"key_type"`
	KeyVersion *scrypto.KeyVersion `json:"key_version"`
}

func (p *protectedAlias) checkAllSet() error {
	switch {
	case p.Algorithm == nil:
		return serrors.WithCtx(ErrMissingProtectedField, "field", "alg")
	case p.KeyType == nil:
		return serrors.WithCtx(ErrMissingProtectedField, "field", "key_type")
	case p.KeyVersion == nil:
		return serrors.WithCtx(ErrMissingProtectedField, "field", "key_version")
	case p.Crit == nil:
		return serrors.WithCtx(ErrMissingProtectedField, "field", "crit")
	default:
		return nil
	}
}

var (
	critASFields        = []string{"key_type", "key_version"}
	packedCritFields, _ = json.Marshal(critASFields)
)

// CritRequest is the "crit" section for the reissuance request (see:
// https://tools.ietf.org/html/rfc7515#section-4.1.11).
type CritRequest struct{}

// UnmarshalJSON checks that all expected elements and no other are in the array.
func (CritRequest) UnmarshalJSON(b []byte) error {
	return scrypto.CheckCrit(b, critASFields)
}

// MarshalJSON returns a json array with the expected crit elements.
func (CritRequest) MarshalJSON() ([]byte, error) {
	return packedCritFields, nil
}

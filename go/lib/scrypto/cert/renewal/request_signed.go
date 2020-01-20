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

package renewal

import (
	"encoding/json"
	"time"

	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/util"
)

type signedRequest struct {
	Payload []byte `json:"payload"`
	*pop
}

type pop struct { // proof-of-possession section
	Protected []byte `json:"protected"`
	Signature []byte `json:"signature"`
}

type requestPayload struct {
	Payload []byte `json:"payload"`
	PoPs    []*pop `json:"signatures"`
}

type protected2 struct {
	Algorithm  string             `json:"alg"`
	KeyType    keyconf.Usage      `json:"key_type"`
	KeyVersion scrypto.KeyVersion `json:"key_version"`
	Crit       []byte             `json:"crit"`
}

// NewSignedRequest returns a signed renewal request in the format of
// a valid json. Input are the keys and the AS certificate.
// s : newSigingKey
// r : newRevocationKey
// c : currentKey
func NewSignedRequest(s, r, c keyconf.Key, crt *cert.AS) ([]byte, error) {
	tm := time.Now()
	return newSignedRequest(s, r, c, crt, tm)
}

func newSignedRequest(s, r, c keyconf.Key, crt *cert.AS, t time.Time) ([]byte, error) {
	for _, k := range []keyconf.Key{s, r, c} {
		if err := k.Validate(); err != nil {
			return nil, err
		}
	}

	if err := crt.Validate(); err != nil {
		return nil, err
	}

	//step 1. f(cert, {s,r}.Public) -> requestInfo
	ri := &RequestInfo{
		Subject:       crt.Subject,
		Version:       crt.Version + 1,
		FormatVersion: 1,
		Description:   "This is a base certificate",
		Validity: &scrypto.Validity{
			NotBefore: util.UnixTime{Time: t},
			NotAfter:  util.UnixTime{Time: t.Add(8760 * time.Hour)},
		},
		Keys: Keys{
			Signing:    KeyMeta{Key: s.Public},
			Revocation: KeyMeta{Key: r.Public},
		},
	}

	//step 2. f(requestInfo, {s,r}.Private) --> requestPayload
	p, err := json.Marshal(ri)
	if err != nil {
		return nil, err
	}

	getPoP := func(k keyconf.Key) *pop {
		m := protected2{
			Algorithm:  k.Algorithm,
			KeyType:    k.Usage,
			KeyVersion: k.Version,
			Crit:       packedCritFields,
		}
		ssp, _ := json.Marshal(m)
		sss, err := scrypto.Sign(scrypto.JWSignatureInput(
			string(ssp), scrypto.Base64.EncodeToString(p)),
			s.Priv, scrypto.Ed25519)
		if err != nil {
			//TODO(karampok). eliminate errors here by validation
			panic(err)
		}

		return &pop{
			Protected: ssp,
			Signature: sss,
		}
	}

	rp := &requestPayload{
		Payload: []byte(scrypto.Base64.EncodeToString(p)),
		PoPs:    []*pop{getPoP(s), getPoP(r)},
	}

	//step 3.  f(requestPayload, current-key.Private) -> signedRequest
	pp, err := json.Marshal(rp)
	if err != nil {
		return nil, err
	}

	sr := &signedRequest{
		Payload: []byte(scrypto.Base64.EncodeToString(pp)),
		pop:     getPoP(c),
	}

	// // Debug function will go away
	// d := func(name string, i interface{}) {
	// 	t, _ := json.MarshalIndent(i, "", "    ")
	// 	fmt.Printf("\n-- %s\n%s\n", name, string(t))
	// }
	// d("requestInfo", ri)
	// d("requestPayload", rp)
	// d("SignedRequest", sr)

	return json.Marshal(sr)
}

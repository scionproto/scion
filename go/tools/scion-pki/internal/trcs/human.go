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

package trcs

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/trc"
	"github.com/scionproto/scion/go/lib/serrors"
)

func runHuman(files []string) error {
	for _, file := range files {
		if err := genHuman(file); err != nil {
			return serrors.WrapStr("unable to generate human output", err, "file", file)
		}
	}
	return nil
}

func genHuman(file string) error {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	var signed trc.Signed
	if err := json.Unmarshal(raw, &signed); err != nil {
		return serrors.WrapStr("unable to parse signed TRC", err, "file", file)
	}
	t, err := signed.EncodedTRC.Decode()
	if err != nil {
		return serrors.WrapStr("unable to parse TRC payload", err, "file", file)
	}
	signatures, err := parseSignatures(signed.Signatures)
	if err != nil {
		return serrors.WrapStr("unable to parse signatures", err, "file", file)
	}
	humanReadable := struct {
		Payload    *trc.TRC    `json:"payload"`
		Signatures []signature `json:"signatures"`
	}{
		Payload:    t,
		Signatures: signatures,
	}
	if raw, err = json.MarshalIndent(humanReadable, "", "  "); err != nil {
		return serrors.WrapStr("unable to write human readable trc", err, "file", file)
	}
	_, err = fmt.Fprintln(os.Stdout, string(raw))
	return err
}

func parseSignatures(packed []trc.Signature) ([]signature, error) {
	var signatures []signature
	for i, s := range packed {
		p, err := s.EncodedProtected.Decode()
		if err != nil {
			return nil, serrors.WrapStr("unable to parse protected meta", err, "idx", i)
		}
		signatures = append(signatures, signature{Protected: p, Signature: s.Signature})
	}
	return signatures, nil
}

type signature struct {
	Protected trc.Protected       `json:"protected"`
	Signature scrypto.JWSignature `json:"signature"`
}

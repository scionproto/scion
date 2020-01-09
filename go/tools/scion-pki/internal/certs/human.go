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

package certs

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/serrors"
)

func runHuman(files []string) error {
	issuers, chains := MatchFiles(files)
	for _, file := range issuers {
		if err := genHumanIssuer(file); err != nil {
			return serrors.WrapStr("unable to display issuer certificate", err, "file", file)
		}
	}
	for _, file := range chains {
		if err := genHumanChain(file); err != nil {
			return serrors.WrapStr("unable to display certificate chain", err, "file", file)
		}
	}
	return nil
}

func genHumanIssuer(file string) error {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	signed, err := cert.ParseSignedIssuer(raw)
	if err != nil {
		return serrors.WrapStr("unable to parse signed issuer certificate", err)
	}
	d, err := decodeIssuer(&signed)
	if err != nil {
		return serrors.WrapStr("unable to decode issuer certificate", err)
	}
	if raw, err = json.MarshalIndent(d, "", "  "); err != nil {
		return serrors.WrapStr("unable to write human readable issuer certificate", err)
	}
	_, err = fmt.Fprintln(os.Stdout, string(raw))
	return err
}

func genHumanChain(file string) error {
	raw, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	signed, err := cert.ParseChain(raw)
	if err != nil {
		return serrors.WrapStr("unable to parse signed certificate chain", err)
	}
	humanReadable := make([]decodedCert, 2)
	humanReadable[0], err = decodeIssuer(&signed.Issuer)
	if err != nil {
		return serrors.WrapStr("unable to decode issuer certificate", err)
	}
	humanReadable[1], err = decodeAS(&signed.AS)
	if err != nil {
		return serrors.WrapStr("unable to decode AS certificate", err)
	}
	if raw, err = json.MarshalIndent(humanReadable, "", "  "); err != nil {
		return serrors.WrapStr("unable to write human readable certificate chain", err)
	}
	_, err = fmt.Fprintln(os.Stdout, string(raw))
	return err
}

type decodedCert struct {
	Payload   interface{}         `json:"payload"`
	Protected interface{}         `json:"protected"`
	Signature scrypto.JWSignature `json:"signature"`
}

func decodeAS(c *cert.SignedAS) (decodedCert, error) {
	var err error
	var d decodedCert
	if d.Payload, err = c.Encoded.Decode(); err != nil {
		return decodedCert{}, err
	}
	if d.Protected, err = c.EncodedProtected.Decode(); err != nil {
		return decodedCert{}, err
	}
	d.Signature = c.Signature
	return d, nil
}

func decodeIssuer(c *cert.SignedIssuer) (decodedCert, error) {
	var err error
	var d decodedCert
	if d.Payload, err = c.Encoded.Decode(); err != nil {
		return decodedCert{}, err
	}
	if d.Protected, err = c.EncodedProtected.Decode(); err != nil {
		return decodedCert{}, err
	}
	d.Signature = c.Signature
	return d, nil
}

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

package decoded

import (
	"fmt"

	"github.com/scionproto/scion/go/lib/scrypto/cert/v2"
	"github.com/scionproto/scion/go/lib/scrypto/trc/v2"
	"github.com/scionproto/scion/go/lib/serrors"
)

// ErrParse indicates that parsign failed.
var ErrParse = serrors.New("parse error")

// TRC is a container for the decoded TRC.
type TRC struct {
	TRC    *trc.TRC
	Signed trc.Signed
	Raw    []byte
}

// DecodeTRC decodes the TRC.
func DecodeTRC(raw []byte) (TRC, error) {
	signed, err := trc.ParseSigned(raw)
	if err != nil {
		return TRC{}, serrors.WithCtx(ErrParse, err, "part", "signed")
	}
	decoded, err := signed.EncodedTRC.Decode()
	if err != nil {
		return TRC{}, serrors.WithCtx(ErrParse, err, "part", "decode payload")
	}
	d := TRC{
		TRC:    decoded,
		Signed: signed,
		Raw:    raw,
	}
	return d, nil
}

func (d TRC) String() string {
	if d.TRC == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ISD%d-V%d", d.TRC.ISD, d.TRC.Version)
}

// Chain is a container for the decoded certificate chain.
type Chain struct {
	Chain  cert.Chain
	AS     *cert.AS
	Issuer *cert.Issuer
	Raw    []byte
}

func (d Chain) String() string {
	if d.AS == nil {
		return "<nil>"
	}
	return fmt.Sprintf("ISD%s-V%d", d.AS.Subject.FileFmt(true), d.AS.Version)
}

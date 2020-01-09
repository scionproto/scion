// Copyright 2018 ETH Zurich
// Copyright 2019 ETH Zurich, Anapaya Systems
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
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/pkicmn"
)

type fullGen struct {
	Dirs    pkicmn.Dirs
	Version scrypto.Version
}

func (g fullGen) Run(asMap pkicmn.ASMap) error {
	cfgs, err := loader{Dirs: g.Dirs, Version: g.Version}.LoadConfigs(asMap.ISDs())
	if err != nil {
		return serrors.WrapStr("unable to load TRC configs", err)
	}
	protos, err := protoGen{Dirs: g.Dirs, Version: g.Version}.Generate(cfgs)
	if err != nil {
		return serrors.WrapStr("unable to generate prototype TRCs", err)
	}
	parts, err := signatureGen{Dirs: g.Dirs, Version: g.Version}.Generate(asMap, cfgs, protos)
	if err != nil {
		return serrors.WrapStr("unable to sign prototype TRCs", err)
	}
	c := combiner{Dirs: g.Dirs}
	combined, err := c.Combine(protos, parts)
	if err != nil {
		return serrors.WrapStr("unable to combine parts and prototype TRC", err)
	}
	if err := (validator{Dirs: c.Dirs}).Validate(combined); err != nil {
		return serrors.WrapStr("invalid combined TRCs generated", err)
	}
	if err := c.Write(combined); err != nil {
		return serrors.WrapStr("unable to write combined TRCs", err)
	}
	return nil
}

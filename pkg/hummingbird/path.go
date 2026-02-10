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

package hummingbird

import (
	"fmt"
	"time"

	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/slayers/path/hummingbird"
	"github.com/scionproto/scion/pkg/slayers/path/scion"
	"github.com/scionproto/scion/pkg/snet"
	"github.com/scionproto/scion/pkg/snet/path"
)

func NewPathFromScion(p snet.Path, timeStamp time.Time) (snet.Path, error) {
	if p == nil {
		return nil, serrors.New("nil path")
	}
	dpPath := p.Dataplane()
	dpath, ok := dpPath.(path.SCION)
	if !ok {
		return nil, serrors.New("can only convert SCION paths", "type", fmt.Sprintf("%T", dpPath))
	}
	// Create a decoded Hummingbird path based on the SCION one.
	dec, err := rawScionToHummingbirdDecoded(dpath.Raw)
	if err != nil {
		return nil, err
	}
	// Create a light snet Hummingbird path containing the decoded Hummingbird one above.
	dpHbirdPath, err := path.NewHummingbirdDataplanePath(dec)
	if err != nil {
		return nil, err
	}

	// Create a new wrapping snet Path to return the new Hummingbird one.
	ret := path.Path{
		Src:           p.Source(),
		Dst:           p.Destination(),
		NextHop:       p.UnderlayNextHop(),
		Meta:          *p.Metadata(),
		DataplanePath: *dpHbirdPath,
	}
	return ret, nil
}

func rawScionToHummingbirdDecoded(p []byte) (*hummingbird.Decoded, error) {
	scionDec := scion.Decoded{}
	if err := scionDec.DecodeFromBytes(p); err != nil {
		return &hummingbird.Decoded{}, err
	}

	dec := &hummingbird.Decoded{}
	dec.ConvertFromScionDecoded(scionDec)
	return dec, nil
}

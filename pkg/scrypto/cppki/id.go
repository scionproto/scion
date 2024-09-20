// Copyright 2020 Anapaya Systems
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

package cppki

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/private/serrors"
	"github.com/scionproto/scion/pkg/scrypto"
)

var (
	// ErrWildcardISD indicates a wildcard ISD.
	ErrWildcardISD = serrors.New("wildcard ISD")
	// ErrReservedNumber indicates that the number is reserved.
	ErrReservedNumber = serrors.New("reserved number")
	// ErrSerialBeforeBase indicates that the serial number is smaller than the
	// base number.
	ErrSerialBeforeBase = serrors.New("serial before base")
	// ErrInvalidTRCIDString indicates that provided string in not valid TRC ID formatted string.
	ErrInvalidTRCIDString = serrors.New("string is not valid TRC ID")
)

// TRCID identifies a TRC.
type TRCID struct {
	ISD    addr.ISD
	Serial scrypto.Version
	Base   scrypto.Version
}

// TRCIDFromString creates new TRCID from the provided string. TRCID string must be in format
// `ISD%d-B%d-S%d`.
func TRCIDFromString(idStr string) (TRCID, error) {
	re := regexp.MustCompile(`^ISD(\d+)-B(\d+)-S(\d+)$`)
	idParts := re.FindStringSubmatch(idStr)
	if len(idParts) != 4 {
		return TRCID{}, ErrInvalidTRCIDString
	}

	isd, err := strconv.ParseUint(idParts[1], 10, 64)
	if err != nil {
		return TRCID{}, err
	}
	base, err := strconv.ParseUint(idParts[2], 10, 64)
	if err != nil {
		return TRCID{}, err
	}
	serial, err := strconv.ParseUint(idParts[3], 10, 64)
	if err != nil {
		return TRCID{}, err
	}

	return TRCID{
		ISD:    addr.ISD(isd),
		Base:   scrypto.Version(base),
		Serial: scrypto.Version(serial),
	}, nil
}

// IsBase indicates if this is a base TRC.
func (id TRCID) IsBase() bool {
	return id.Serial == id.Base
}

// Validate validates the TRC ID.
func (id TRCID) Validate() error {
	if id.ISD == 0 {
		return ErrWildcardISD
	}
	if id.Base > id.Serial {
		return serrors.JoinNoStack(ErrSerialBeforeBase, nil, "serial", id.Serial, "base", id.Base)
	}
	// Serial != 0 is implied by this, and the check above.
	if id.Base == 0 {
		return ErrReservedNumber
	}
	return nil
}

func (id TRCID) String() string {
	return fmt.Sprintf("ISD%d-B%d-S%d", id.ISD, id.Base, id.Serial)
}

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

package trcs

import (
	"time"

	"github.com/scionproto/scion/pkg/scrypto/cppki"
	"github.com/scionproto/scion/scion-pki/conf"
)

// CreatePayload creates the ASN.1 payload for the TRC from the given
// configuration.
func CreatePayload(cfg conf.TRC, pred *cppki.TRC) (*cppki.TRC, error) {
	certs, err := cfg.Certificates(pred)
	if err != nil {
		return nil, err
	}

	v := cfg.Validity.Eval(time.Now())
	trc := &cppki.TRC{
		Version: 1,
		ID: cppki.TRCID{
			ISD:    cfg.ISD,
			Base:   cfg.BaseVersion,
			Serial: cfg.SerialVersion,
		},
		Validity:          v,
		GracePeriod:       cfg.GracePeriod.Duration,
		NoTrustReset:      cfg.NoTrustReset,
		Votes:             cfg.Votes,
		Quorum:            int(cfg.VotingQuorum),
		CoreASes:          cfg.CoreASes,
		AuthoritativeASes: cfg.AuthoritativeASes,
		Description:       cfg.Description,
		Certificates:      certs,
	}
	if err := trc.Validate(); err != nil {
		return nil, err
	}
	return trc, nil
}

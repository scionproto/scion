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

package conf_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/xtest"
	"github.com/scionproto/scion/go/tools/scion-pki/internal/v2/conf"
)

func TestAsValidate(t *testing.T) {
	tests := map[string]struct {
		Modify         func(*conf.ASCfg)
		ExpectedErrMsg string
	}{
		"valid AS cert from template": {
			Modify: func(cfg *conf.ASCfg) {
				*cfg = *conf.NewTemplateASCfg(xtest.MustParseIA("1-ff00:0:110"), 4, true, true)
				cfg.Update()
			},
		},
		"valid AS cert from template with modifications": {
			Modify: func(cfg *conf.ASCfg) {
				*cfg = *conf.NewTemplateASCfg(xtest.MustParseIA("1-ff00:0:110"), 4, false, true)
				cfg.AS.OptionalDistributionPoints = []addr.IA{xtest.MustParseIA("2-ff00:0:210")}
				cfg.AS.EncAlgorithm = ""
				cfg.AS.SignAlgorithm = ""
				cfg.Update()
			},
		},
		"valid AS cert": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.Issuer = nil
				cfg.PrimaryKeyAlgorithms = nil
			},
		},
		"valid AS and issuer cert": {
			Modify: func(cfg *conf.ASCfg) {},
		},
		"empty AS": {
			Modify: func(cfg *conf.ASCfg) {
				*cfg = conf.ASCfg{}
			},
			ExpectedErrMsg: conf.ErrASCertMissing,
		},
		"invalid optional distribution points": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.AS.RawOptDistPoints = []string{"2-0"}
			},
			ExpectedErrMsg: conf.ErrInvalidOptDistPoint,
		},
		"empty Issuer inside AS Cert": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.AS.RawIssuerIA = ""
			},
			ExpectedErrMsg: conf.ErrIssuerMissing,
		},
		"wildcard Issuer inside AS Cert": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.AS.RawIssuerIA = "1-0"
			},
			ExpectedErrMsg: conf.ErrInvalidIssuer,
		},
		"invalid IssuerCertVersion": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.AS.IssuerCertVersion = 0
			},
			ExpectedErrMsg: conf.ErrInvalidIssuerCertVersion,
		},
		"invalid TRCVersion": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.Issuer.TRCVersion = 0
			},
			ExpectedErrMsg: conf.ErrInvalidIssuerTRCVersion,
		},
		"invalid Version": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.AS.Version = 0
			},
			ExpectedErrMsg: conf.ErrVersionNotSet,
		},
		"invalid RawValidity": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.Issuer.RawValidity = "3"
			},
			ExpectedErrMsg: conf.ErrInvalidValidityDuration,
		},
		"zero validity": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.AS.RawValidity = ""
			},
			ExpectedErrMsg: conf.ErrValidityDurationNotSet,
		},
		"invalid sign algorithm": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.AS.SignAlgorithm = scrypto.Curve25519xSalsa20Poly1305
			},
			ExpectedErrMsg: conf.ErrInvalidSignAlgorithm,
		},
		"invalid revocation algorithm": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.AS.RevAlgorithm = scrypto.Curve25519xSalsa20Poly1305
			},
			ExpectedErrMsg: conf.ErrInvalidSignAlgorithm,
		},
		"invalid issuing algorithm": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.Issuer.IssuingAlgorithm = scrypto.Curve25519xSalsa20Poly1305
			},
			ExpectedErrMsg: conf.ErrInvalidSignAlgorithm,
		},
		"invalid encryption algorithm": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.AS.EncAlgorithm = scrypto.Ed25519
			},
			ExpectedErrMsg: conf.ErrInvalidEncAlgorithm,
		},
		"invalid online key": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.PrimaryKeyAlgorithms.Online = scrypto.Curve25519xSalsa20Poly1305
			},
			ExpectedErrMsg: conf.ErrInvalidSignAlgorithm,
		},
		"invalid offline key": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.PrimaryKeyAlgorithms.Offline = scrypto.Curve25519xSalsa20Poly1305
			},
			ExpectedErrMsg: conf.ErrInvalidSignAlgorithm,
		},
		"invalid issuing key": {
			Modify: func(cfg *conf.ASCfg) {
				cfg.PrimaryKeyAlgorithms.Issuing = scrypto.Curve25519xSalsa20Poly1305
			},
			ExpectedErrMsg: conf.ErrInvalidSignAlgorithm,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			as := conf.ASCfg{
				AS: &conf.AS{
					BaseCert: &conf.BaseCert{
						Version:          1,
						Description:      "AS certificate",
						RawOptDistPoints: []string{"2-ff00:0:210"},
						NotBefore:        0,
						RawValidity:      "3d",
						RevAlgorithm:     scrypto.Ed25519,
					},
					EncAlgorithm:      scrypto.Curve25519xSalsa20Poly1305,
					SignAlgorithm:     scrypto.Ed25519,
					RawIssuerIA:       "1-ff00:0:110",
					IssuerCertVersion: 2,
				},
				Issuer: &conf.Issuer{
					BaseCert: &conf.BaseCert{
						Version:          2,
						Description:      "Issuer certificate",
						RawOptDistPoints: []string{"2-ff00:0:210"},
						NotBefore:        0,
						RawValidity:      "7d",
						RevAlgorithm:     scrypto.Ed25519,
					},
					IssuingAlgorithm: scrypto.Ed25519,
					TRCVersion:       4,
				},
				PrimaryKeyAlgorithms: &conf.PrimaryKeyAlgorithms{
					Online:  scrypto.Ed25519,
					Offline: scrypto.Ed25519,
					Issuing: scrypto.Ed25519,
				},
			}
			test.Modify(&as)
			err := as.Validate()
			if test.ExpectedErrMsg == "" {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.ExpectedErrMsg)
			}
		})
	}
}

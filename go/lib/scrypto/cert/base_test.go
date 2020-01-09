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

package cert_test

import (
	"testing"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	ia110 = xtest.MustParseIA("1-ff00:0:110")
	ia210 = xtest.MustParseIA("2-ff00:0:210")
)

func TestBaseValidate(t *testing.T) {
	tests := map[string]struct {
		Modify         func(*cert.Base)
		ExpectedErrMsg error
	}{
		"Valid": {
			Modify: func(_ *cert.Base) {},
		},
		"Subject wildcard AS": {
			Modify: func(c *cert.Base) {
				c.Subject.A = 0
			},
			ExpectedErrMsg: cert.ErrInvalidSubject,
		},
		"Subject wildcard ISD": {
			Modify: func(c *cert.Base) {
				c.Subject.I = 0
			},
			ExpectedErrMsg: cert.ErrInvalidSubject,
		},
		"DistributionPoint wildcard": {
			Modify: func(c *cert.Base) {
				c.OptionalDistributionPoints = append(c.OptionalDistributionPoints, addr.IA{I: 1})
			},
			ExpectedErrMsg: cert.ErrInvalidDistributionPoint,
		},
		"Wrong validity period": {
			Modify: func(c *cert.Base) {
				c.Validity.NotAfter.Time = c.Validity.NotBefore.Time
			},
			ExpectedErrMsg: cert.ErrInvalidValidityPeriod,
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			c := newBaseCert(time.Now())
			test.Modify(&c)
			err := c.Validate()
			xtest.AssertErrorsIs(t, err, test.ExpectedErrMsg)
		})
	}
}

func newBaseCert(notBefore time.Time) cert.Base {
	now := notBefore.Truncate(time.Second)
	c := cert.Base{
		Subject:       ia110,
		Version:       1,
		FormatVersion: 1,
		Description:   "This is a base certificate",
		Validity: &scrypto.Validity{
			NotBefore: util.UnixTime{Time: now},
			NotAfter:  util.UnixTime{Time: now.Add(8760 * time.Hour)},
		},
		OptionalDistributionPoints: []addr.IA{ia210},
	}
	return c
}

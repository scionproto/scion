// Copyright 2018 ETH Zurich
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

package conf

import (
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/common"
)

type asConfTestStructure struct {
	scenario string
	as       *As
	err      string
}

func TestValidatingAsConf(t *testing.T) {
	Convey("Given an AS configuration", t, func() {
		tests := []asConfTestStructure{
			{
				scenario: "With empty AS",
				as:       &As{},
				err:      ErrAsCertMissing,
			},
			{
				scenario: "With empty Issuer inside AS Cert",
				as: &As{
					AsCert: &AsCert{
						Issuer: "",
						BaseCert: &BaseCert{
							TRCVersion:  1,
							Version:     1,
							RawValidity: "180s",
						},
					},
				},
				err: ErrIssuerMissing,
			},
			{
				scenario: "With empty Issuer in different format inside AS Cert",
				as: &As{
					AsCert: &AsCert{
						Issuer: "0-0",
						BaseCert: &BaseCert{
							TRCVersion:  1,
							Version:     1,
							RawValidity: "180s",
						},
					},
				},
				err: ErrIssuerMissing,
			},
			{
				scenario: "With invalid TRCVersion inside BaseCert",
				as: &As{
					AsCert: &AsCert{
						Issuer: "1-ff00:0:10",
						BaseCert: &BaseCert{
							Version:     1,
							RawValidity: "180s",
						},
					},
				},
				err: ErrTRCVersionNotSet,
			},
			{
				scenario: "With invalid Version for BaseCert",
				as: &As{
					AsCert: &AsCert{
						Issuer: "1-ff00:0:10",
						BaseCert: &BaseCert{
							TRCVersion:  1,
							RawValidity: "180s",
						},
					},
				},
				err: ErrVersionNotSet,
			},
			{
				scenario: "With invalid RawValidity for BaseCert",
				as: &As{
					AsCert: &AsCert{
						Issuer: "1-ff00:0:10",
						BaseCert: &BaseCert{
							TRCVersion:  1,
							Version:     1,
							RawValidity: "180",
						},
					},
				},
				err: ErrInvalidValidityDuration,
			},
			{
				scenario: "With validity set to 0 for BaseCert",
				as: &As{
					AsCert: &AsCert{
						Issuer: "1-ff00:0:10",
						BaseCert: &BaseCert{
							TRCVersion: 1,
							Version:    1,
						},
					},
				},
				err: ErrValidityDurationNotSet,
			},
			{
				scenario: "With valid AS Cert",
				as: &As{
					AsCert: &AsCert{
						Issuer: "1-ff00:0:10",
						BaseCert: &BaseCert{
							TRCVersion:  1,
							Version:     1,
							RawValidity: "180s",
						},
					},
				},
				err: "",
			},
		}
		for _, test := range tests {
			Convey(test.scenario, func() {
				err := test.as.validate()
				if test.err != "" {
					be := err.(common.BasicError)
					So(be.Msg, ShouldEqual, test.err)
				} else {
					So(err, ShouldBeNil)
				}
			})
		}
	})
}

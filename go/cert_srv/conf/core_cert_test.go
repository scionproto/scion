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
	"io/ioutil"
	"os"
	"testing"

	. "github.com/smartystreets/goconvey/convey"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
)

func Test_NewCoreCertStore(t *testing.T) {
	Convey("NewCoreCertStore should initialize correctly", t, func() {
		chain, err := cert.ChainFromFile("testdata/ISD1-AS10-V1.crt", false)
		SoMsg("err chain", err, ShouldBeNil)
		SoMsg("chain", chain, ShouldNotBeNil)
		ia := chain.Core.Subject
		chain.Core.Version = 2
		_, db, cleanF := newTestCoreCertStore(ia, chain, t)
		defer cleanF()

		Convey("Init with no chain", func() {
			_, err := NewCoreCertStore(ia, chain, db)
			SoMsg("err", err, ShouldBeNil)
		})

		Convey("Init with older chain", func() {
			chain.Core.Version -= 1
			_, err := NewCoreCertStore(ia, chain, db)
			SoMsg("err", err, ShouldBeNil)
		})
		Convey("Init with newer chain", func() {
			chain.Core.Version += 1
			_, err := NewCoreCertStore(ia, chain, db)
			SoMsg("err", err, ShouldBeNil)
		})

	})
	Convey("NewCoreCertStore should fail if db empty and no chain provided", t, func() {
		db, cleanF := newTestDatabase(t)
		defer cleanF()
		ia := addr.IA{I: 1, A: 10}
		_, err := NewCoreCertStore(ia, nil, db)
		SoMsg("err", err, ShouldNotBeNil)
	})
	Convey("NewCoreCertStore should fail if mismatching ISD-AS", t, func() {
		db, cleanF := newTestDatabase(t)
		defer cleanF()
		chain, err := cert.ChainFromFile("testdata/ISD1-AS10-V1.crt", false)
		SoMsg("err chain", err, ShouldBeNil)
		SoMsg("chain", chain, ShouldNotBeNil)
		ia := addr.IA{I: 1, A: 1}
		_, err = NewCoreCertStore(ia, nil, db)
		SoMsg("err", err, ShouldNotBeNil)
	})

}

func Test_Set(t *testing.T) {
	Convey("Initialize store and load Cert", t, func() {
		chain, err := cert.ChainFromFile("testdata/ISD1-AS10-V1.crt", false)
		SoMsg("err chain", err, ShouldBeNil)
		SoMsg("chain", chain, ShouldNotBeNil)
		s, _, cleanF := newTestCoreCertStore(chain.Core.Subject, chain, t)
		defer cleanF()

		Convey("Set certificate", func() {
			chain.Core.Version = 2
			err := s.Set(chain.Core)
			SoMsg("err", err, ShouldBeNil)
			Convey("Set older certificate", func() {
				err := s.Set(chain.Core)
				SoMsg("err", err, ShouldNotBeNil)
			})
			Convey("Get older certificate", func() {
				crt, err := s.Get()
				SoMsg("err", err, ShouldBeNil)
				SoMsg("cert", crt, ShouldResemble, chain.Core)
			})
		})
		Convey("Set certificate mismatching ia", func() {
			err := s.Set(chain.Leaf)
			SoMsg("err", err, ShouldNotBeNil)
		})
	})
}

func Test_Get(t *testing.T) {
	Convey("Initialize store and load Cert", t, func() {
		chain, err := cert.ChainFromFile("testdata/ISD1-AS10-V1.crt", false)
		SoMsg("err chain", err, ShouldBeNil)
		SoMsg("chain", chain, ShouldNotBeNil)
		s, _, cleanF := newTestCoreCertStore(chain.Core.Subject, chain, t)
		defer cleanF()

		Convey("Get certificate", func() {
			crt, err := s.Get()
			SoMsg("err", err, ShouldBeNil)
			SoMsg("cert", crt, ShouldResemble, chain.Core)
		})
	})
}

func newTestCoreCertStore(ia addr.IA, chain *cert.Chain, t *testing.T) (*CoreCertStore,
	*trustdb.DB, func()) {
	db, f := newTestDatabase(t)
	s, err := NewCoreCertStore(ia, chain, db)
	if err != nil {
		t.Fatalf("unable to initialize database")
	}
	return s, db, f
}

func newTestDatabase(t *testing.T) (*trustdb.DB, func()) {
	file, err := ioutil.TempFile("", "db-test-")
	if err != nil {
		t.Fatalf("unable to create temp file")
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		t.Fatalf("unable to close temp file")
	}
	db, err := trustdb.New(name)
	if err != nil {
		t.Fatalf("unable to initialize database")
	}
	return db, func() {
		db.Close()
		os.Remove(name)
	}
}

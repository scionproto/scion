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
	"database/sql"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/crypto/cert"
	"github.com/scionproto/scion/go/lib/infra/modules/trust/trustdb"
)

const (
	getCoreCertVersionStr = `
			SELECT max(Version) FROM Certs WHERE IsdID=? and AsID=?
		`
	insertCoreCertStr = `
			INSERT INTO Certs (IsdID, AsID, Version, Data) SELECT ?,?,?,? 
			WHERE NOT EXISTS(SELECT 1 FROM Certs WHERE IsdID=? and AsID=? and Version>=?)
		`
)

// CoreCertStore keeps track of the newest version of the core certificate of this core AS.
type CoreCertStore struct {
	db                 *trustdb.DB
	ia                 addr.IA
	getCoreCertVerStmt *sql.Stmt
	insertCoreCertStmt *sql.Stmt
}

// NewCoreCertStore loads the CoreCertStore.
func NewCoreCertStore(ia addr.IA, chain *cert.Chain, db *trustdb.DB) (*CoreCertStore, error) {
	var err error
	s := &CoreCertStore{
		ia: ia,
		db: db,
	}
	if s.getCoreCertVerStmt, err = s.db.Prepare(getCoreCertVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getCoreCertVer", err)
	}
	if s.insertCoreCertStmt, err = s.db.Prepare(insertCoreCertStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertCoreCert", err)
	}
	var ver uint64 = 0
	err = s.getCoreCertVerStmt.QueryRow().Scan(&ver)
	if chain == nil && err != nil {
		return nil, common.NewBasicError("No chain provided and core cert not set", nil)
	}
	if !chain.Core.Subject.Eq(ia) {
		return nil, common.NewBasicError("Ia does not match core certificate subject", nil,
			"ia", ia, "subject", chain.Core.Subject)
	}
	if chain.Core.Version > ver || err != nil {
		raw, err := chain.Core.JSON(false)
		if err != nil {
			return nil, err
		}
		ver = chain.Core.Version
		if _, err = s.insertCoreCertStmt.Exec(ia.I, ia.A, ver, raw, ia.I, ia.A, ver); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Set sets the core certificate. An error is returned, if there already exists a core cert with
// higher version number.
func (s *CoreCertStore) Set(crt *cert.Certificate) error {
	if !crt.Subject.Eq(s.ia) {
		return common.NewBasicError("Ia does not match core certificate subject", nil,
			"ia", s.ia, "subject", crt.Subject)
	}
	raw, err := crt.JSON(false)
	if err != nil {
		return common.NewBasicError("Unable to convert to JSON", err)
	}
	res, err := s.insertCoreCertStmt.Exec(s.ia.I, s.ia.A, crt.Version, raw,
		s.ia.I, s.ia.A, crt.Version)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	} else if affected == 0 {
		var ver uint64
		err = s.getCoreCertVerStmt.QueryRow().Scan(&ver)
		return common.NewBasicError("Unable to insert max certificate", nil, "err",
			"Certificate with higher version present")
	}

	return nil
}

// Get returns the core certificate.
func (s *CoreCertStore) Get() (*cert.Certificate, error) {
	return s.db.GetCertMaxVersion(s.ia)
}

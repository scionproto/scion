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
	getIssuerCertVersionStr = `
			SELECT max(Version) FROM IssuerCerts WHERE IsdID=? and AsID=?
		`
	insertIssuerCertStr = `
			INSERT INTO IssuerCerts (IsdID, AsID, Version, Data) SELECT ?,?,?,? 
			WHERE NOT EXISTS(SELECT 1 FROM IssuerCerts WHERE IsdID=? and AsID=? and Version>=?)
		`
)

// IssuerCertStore keeps track of the newest version of the issuer certificate of this AS.
type IssuerCertStore struct {
	db                   *trustdb.DB
	ia                   addr.IA
	getIssuerCertVerStmt *sql.Stmt
	insertIssuerCertStmt *sql.Stmt
}

// NewIssuerCertStore loads the IssuerCertStore.
func NewIssuerCertStore(ia addr.IA, chain *cert.Chain, db *trustdb.DB) (*IssuerCertStore, error) {
	var err error
	s := &IssuerCertStore{
		ia: ia,
		db: db,
	}
	if s.getIssuerCertVerStmt, err = s.db.Prepare(getIssuerCertVersionStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare getIssuerCertVersion", err)
	}
	if s.insertIssuerCertStmt, err = s.db.Prepare(insertIssuerCertStr); err != nil {
		return nil, common.NewBasicError("Unable to prepare insertIssuerCert", err)
	}
	var ver uint64
	err = s.getIssuerCertVerStmt.QueryRow().Scan(&ver)
	if chain == nil && err != nil {
		return nil, common.NewBasicError("No chain provided and issuer cert not set", nil)
	}
	if !chain.Issuer.Subject.Eq(ia) {
		return nil, common.NewBasicError("Ia does not match issuer certificate subject", nil,
			"ia", ia, "subject", chain.Issuer.Subject)
	}
	if chain.Issuer.Version > ver || err != nil {
		raw, err := chain.Issuer.JSON(false)
		if err != nil {
			return nil, err
		}
		ver = chain.Issuer.Version
		if _, err = s.insertIssuerCertStmt.Exec(ia.I, ia.A, ver, raw, ia.I, ia.A, ver); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// Set sets the issuer certificate. An error is returned, if there already exists a issuer cert with
// higher version number.
func (s *IssuerCertStore) Set(crt *cert.Certificate) error {
	if !crt.Subject.Eq(s.ia) {
		return common.NewBasicError("Ia does not match issuer certificate subject", nil,
			"ia", s.ia, "subject", crt.Subject)
	}
	raw, err := crt.JSON(false)
	if err != nil {
		return common.NewBasicError("Unable to convert to JSON", err)
	}
	res, err := s.insertIssuerCertStmt.Exec(s.ia.I, s.ia.A, crt.Version, raw,
		s.ia.I, s.ia.A, crt.Version)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	} else if affected == 0 {
		var ver uint64
		err = s.getIssuerCertVerStmt.QueryRow().Scan(&ver)
		return common.NewBasicError("Unable to insert max certificate", nil, "err",
			"Certificate with higher version present")
	}

	return nil
}

// Get returns the issuer certificate.
func (s *IssuerCertStore) Get() (*cert.Certificate, error) {
	return s.db.GetIssCertMaxVersion(s.ia)
}

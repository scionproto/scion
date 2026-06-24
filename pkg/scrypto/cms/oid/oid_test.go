package oid

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMLDSAOIDs(t *testing.T) {
	assert.Equal(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17},
		SignatureAlgorithmMLDSA44,
		"SignatureAlgorithmMLDSA44 OID mismatch",
	)
	assert.Equal(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18},
		SignatureAlgorithmMLDSA65,
		"SignatureAlgorithmMLDSA65 OID mismatch",
	)
	assert.Equal(t,
		asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19},
		SignatureAlgorithmMLDSA87,
		"SignatureAlgorithmMLDSA87 OID mismatch",
	)
}

func TestMLDSASignatureAlgorithmToX509SignatureAlgorithm(t *testing.T) {
	assert.Equal(t,
		x509.MLDSA44,
		SignatureAlgorithmToX509SignatureAlgorithm[SignatureAlgorithmMLDSA44.String()],
		"MLDSA44 x509 mapping mismatch",
	)
	assert.Equal(t,
		x509.MLDSA65,
		SignatureAlgorithmToX509SignatureAlgorithm[SignatureAlgorithmMLDSA65.String()],
		"MLDSA65 x509 mapping mismatch",
	)
	assert.Equal(t,
		x509.MLDSA87,
		SignatureAlgorithmToX509SignatureAlgorithm[SignatureAlgorithmMLDSA87.String()],
		"MLDSA87 x509 mapping mismatch",
	)
}

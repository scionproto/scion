package renewal_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/scionproto/scion/go/lib/keyconf"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/scrypto/cert"
	"github.com/scionproto/scion/go/lib/scrypto/cert/renewal"
	"github.com/scionproto/scion/go/lib/util"
	"github.com/scionproto/scion/go/lib/xtest"
)

var (
	ccert = newCert()

	//skPub, skPriv, _ = scrypto.GenKeyPair(scrypto.Ed25519)
	skPub, skPriv = "e2c1f8c483077d345dcebf2bc6a133051b29d1eb6d7decd862fe4689df47" +
		"c375c4ab34f8849fd5024c1710f187921feb1db27161e2ddb7c05ab6ca4b3e155157",
		"c4ab34f8849fd5024c1710f187921feb1db27161e2ddb7c05ab6ca4b3e155157"

	// rkPub, rkPriv, _ = scrypto.GenKeyPair(scrypto.Ed25519)
	rkPub, rkPriv = "c0c700869dae3ad40bdbff6808c12e0c23ac39a8235c09798aa75334304e" +
		"b384753f23a6e6390ff419f308e32d8706b9b4e8c79fe74a9446a4fa1663820f8148",
		"753f23a6e6390ff419f308e32d8706b9b4e8c79fe74a9446a4fa1663820f8148"

	// ckPub, ckPriv, _ = scrypto.GenKeyPair(scrypto.Ed25519)
	ckPub, ckPriv = "9a0fa05a864af7cc7da18a2cf23294997100653098b3337d54af1dfbdc69" +
		"2023a8b4b32f8770d1ee9dd0a7b0284865b36b5e823be0cdedfb1d643160ea1eac05",
		"a8b4b32f8770d1ee9dd0a7b0284865b36b5e823be0cdedfb1d643160ea1eac05"

	sigResult = "cKWdBxGgpGTAhENqSNBBO8pdSn2RRrCjy6+iKcO6xvsyUOR1Y5STHPh2Ua2qX3le" +
		"412p6ACUFYWzwDvDKV2HCQ=="
)

func newCert() *cert.AS {
	now := time.Now()
	return &cert.AS{
		Base: cert.Base{
			Subject:       xtest.MustParseIA("1-ff00:0:110"),
			Version:       1,
			FormatVersion: 1,
			Description:   "This is a base certificate",
			Validity: &scrypto.Validity{
				NotBefore: util.UnixTime{Time: now},
				NotAfter:  util.UnixTime{Time: now.Add(8760 * time.Hour)},
			},
			Keys: map[cert.KeyType]scrypto.KeyMeta{
				cert.SigningKey:    {},
				cert.EncryptionKey: {},
				cert.RevocationKey: {},
			},
		},
		Issuer: cert.IssuerCertID{
			IA: xtest.MustParseIA("1-ff00:0:120"),
		},
	}
}

func TestNewSignedRequest(t *testing.T) {
	tests := map[string]struct {
		cert       *cert.AS
		keys       map[string]keyconf.Key
		assertFunc assert.ErrorAssertionFunc
	}{
		"error when invalid key": {
			cert: ccert,
			keys: map[string]keyconf.Key{
				"s": {},
				"r": {},
				"c": {},
			},
			assertFunc: assert.Error,
		},
		"error when invalid cert": {
			cert: nil,
			keys: map[string]keyconf.Key{
				"s": {},
			},
			assertFunc: assert.Error,
		},
	}
	for tn, tc := range tests {
		t.Run(tn, func(t *testing.T) {
			_, err := renewal.NewSignedRequest(
				tc.keys["s"], tc.keys["r"], tc.keys["c"], tc.cert)
			tc.assertFunc(t, err)
			if err != nil {
				return
			}
		})
	}

	t.Run("happy path", func(t *testing.T) {
		s := keyconf.Key{
			ID: keyconf.ID{
				Usage: keyconf.ASSigningKey,
			},
			Algorithm: scrypto.Ed25519,
			Priv:      []byte(skPriv),
			Public:    []byte(skPub),
			Type:      keyconf.PublicKey,
		}
		r := keyconf.Key{
			ID: keyconf.ID{
				Usage: keyconf.ASRevocationKey,
			},
			Algorithm: scrypto.Ed25519,
			Priv:      []byte(rkPriv),
			Public:    []byte(rkPub),
			Type:      keyconf.PublicKey,
		}
		c := keyconf.Key{
			ID: keyconf.ID{
				Usage: keyconf.ASSigningKey,
			},
			Algorithm: scrypto.Ed25519,
			Priv:      []byte(ckPriv),
			Public:    []byte(ckPub),
			Type:      keyconf.PublicKey,
		}

		t.Logf("when time is fixed at %v", renewal.FixedTime)
		raw, err := renewal.NewSignedRequestFixedTime(s, r, c, ccert)
		assert.NoError(t, err)

		jsonMap := make(map[string]interface{})
		assert.NoError(t, json.Unmarshal([]byte(raw), &jsonMap))
		assert.Equal(t, jsonMap["signature"], sigResult)
	})
}

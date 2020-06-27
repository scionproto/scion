package trust

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"path/filepath"

	"github.com/scionproto/scion/go/lib/log"
)

// LoadingRing is a key ring that loads the private keys from the configured
// directory.
type LoadingRing struct {
	Dir string
}

// PrivateKeys loads all private keys that are in PKCS#8 format from the directory.
func (r LoadingRing) PrivateKeys(ctx context.Context) ([]crypto.Signer, error) {
	files, err := filepath.Glob(filepath.Join(r.Dir, "*.key"))
	if err != nil {
		return nil, err
	}
	log.FromCtx(ctx).Debug("available keys:", "files", files)

	var signers []crypto.Signer
	for _, file := range files {
		raw, err := ioutil.ReadFile(file)
		if err != nil {
			log.FromCtx(ctx).Info("Error reading key file", "file", file, "err", err)
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil || block.Type != "PRIVATE KEY" {
			continue
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			continue
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			continue
		}
		signers = append(signers, signer)
	}
	return signers, nil
}

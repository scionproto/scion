package trust

import (
	"context"
	"net"
	"time"

	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/ctrl"
	"github.com/scionproto/scion/go/lib/ctrl/cert_mgmt"
	"github.com/scionproto/scion/go/lib/infra"
	"github.com/scionproto/scion/go/lib/scrypto"
	"github.com/scionproto/scion/go/lib/serrors"
	"github.com/scionproto/scion/go/proto"
)

type verifier struct {
	//server net.Addr //TODO(karampok). discuss: who is adding the server.

	GracePeriod time.Duration //timeskew allowed
	SRC         *ctrl.SignSrcDef
	Store       CryptoProvider
	IA          addr.IA
}

// NewVerifier ...
func NewVerifier(provider CryptoProvider) infra.Verifier {
	return &verifier{
		Store: provider,
	}
}

func ignoreSign(p *ctrl.Pld, sign *proto.SignS) bool {
	u0, _ := p.Union()
	outer, ok := u0.(*cert_mgmt.Pld)
	if !ok {
		return false
	}
	u1, _ := outer.Union()
	switch u1.(type) {
	case *cert_mgmt.Chain, *cert_mgmt.TRC:
		return true
	case *cert_mgmt.ChainReq, *cert_mgmt.TRCReq:
		if sign == nil || sign.Type == proto.SignType_none {
			return true
		}
	}
	return false
}

func (v *verifier) VerifyPld(ctx context.Context, spld *ctrl.SignedPld) (*ctrl.Pld, error) {
	cpld, err := ctrl.NewPldFromRaw(spld.Blob)
	if err != nil {
		return nil, err
	}

	if ignoreSign(cpld, spld.Sign) {
		return cpld, nil
	}

	sign := spld.Sign

	if age := time.Now().Sub(sign.Time()); age < 10*time.Second { // check will go away
		return nil, serrors.New("Invalid timestamp. Signature age", "age", age)
	}

	if err := v.Verify(ctx, spld.Blob, spld.Sign); err != nil {
		return nil, err
	}
	return cpld, nil
}

//TODO(karampok). discuss: who is using that?
func (v *verifier) Verify(ctx context.Context, msg common.RawBytes, sign *proto.SignS) error {
	if err := sign.Valid(v.GracePeriod); err != nil {
		return err
	}

	//TODO(karampok). discuss: do we need to re-initialize, when that happens?
	//Do we need anything else other than  IA?
	// remoteIA=ctrl.NewSignSrcDefFromRaw(sign.Src).IA
	f := func(s *ctrl.SignSrcDef, b common.RawBytes) (*ctrl.SignSrcDef, error) {
		if s != nil {
			return s, nil
		}
		n, err := ctrl.NewSignSrcDefFromRaw(b)
		return &n, err
	}

	t, err := f(v.SRC, sign.Src)
	if err != nil {
		return err
	}
	v.SRC = t

	if !v.IA.Equal(v.SRC.IA) {
		return serrors.New("IA does not match bound source", "expected", v.IA, "actual", v.SRC.IA)
	}

	//opts := infra.ChainOpts{}
	//		TrustStoreOpts: infra.TrustStoreOpts{Server: v.server},
	//	}
	key, err := v.Store.GetASKey(ctx, v.SRC.IA.String(), nil)
	if err != nil {
		return err
	}

	return scrypto.VerifyED25519(key, msg, sign)
}

func (v *verifier) WithServer(server net.Addr) infra.Verifier {
	verifier := *v
	//	verifier.server = server
	return &verifier
}

func (v *verifier) WithIA(ia addr.IA) infra.Verifier {
	verifier := *v
	verifier.IA = ia
	return &verifier
}

func (v *verifier) WithSrc(src ctrl.SignSrcDef) infra.Verifier {
	verifier := *v
	verifier.SRC = &src
	return &verifier
}

func (v *verifier) WithSignatureTimestampRange(t infra.SignatureTimestampRange) infra.Verifier {
	//TODO(karampok). discuss: do we need it?
	return nil
}

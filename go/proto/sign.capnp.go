// Code generated by capnpc-go. DO NOT EDIT.

package proto

import (
	capnp "zombiezen.com/go/capnproto2"
	text "zombiezen.com/go/capnproto2/encoding/text"
	schemas "zombiezen.com/go/capnproto2/schemas"
)

type SignedBlob struct{ capnp.Struct }

// SignedBlob_TypeID is the unique identifier for the type SignedBlob.
const SignedBlob_TypeID = 0x9f32478537fae352

func NewSignedBlob(s *capnp.Segment) (SignedBlob, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return SignedBlob{st}, err
}

func NewRootSignedBlob(s *capnp.Segment) (SignedBlob, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return SignedBlob{st}, err
}

func ReadRootSignedBlob(msg *capnp.Message) (SignedBlob, error) {
	root, err := msg.RootPtr()
	return SignedBlob{root.Struct()}, err
}

func (s SignedBlob) String() string {
	str, _ := text.Marshal(0x9f32478537fae352, s.Struct)
	return str
}

func (s SignedBlob) Blob() ([]byte, error) {
	p, err := s.Struct.Ptr(0)
	return []byte(p.Data()), err
}

func (s SignedBlob) HasBlob() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s SignedBlob) SetBlob(v []byte) error {
	return s.Struct.SetData(0, v)
}

func (s SignedBlob) Sign() (Sign, error) {
	p, err := s.Struct.Ptr(1)
	return Sign{Struct: p.Struct()}, err
}

func (s SignedBlob) HasSign() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s SignedBlob) SetSign(v Sign) error {
	return s.Struct.SetPtr(1, v.Struct.ToPtr())
}

// NewSign sets the sign field to a newly
// allocated Sign struct, preferring placement in s's segment.
func (s SignedBlob) NewSign() (Sign, error) {
	ss, err := NewSign(s.Struct.Segment())
	if err != nil {
		return Sign{}, err
	}
	err = s.Struct.SetPtr(1, ss.Struct.ToPtr())
	return ss, err
}

// SignedBlob_List is a list of SignedBlob.
type SignedBlob_List struct{ capnp.List }

// NewSignedBlob creates a new list of SignedBlob.
func NewSignedBlob_List(s *capnp.Segment, sz int32) (SignedBlob_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2}, sz)
	return SignedBlob_List{l}, err
}

func (s SignedBlob_List) At(i int) SignedBlob { return SignedBlob{s.List.Struct(i)} }

func (s SignedBlob_List) Set(i int, v SignedBlob) error { return s.List.SetStruct(i, v.Struct) }

func (s SignedBlob_List) String() string {
	str, _ := text.MarshalList(0x9f32478537fae352, s.List)
	return str
}

// SignedBlob_Promise is a wrapper for a SignedBlob promised by a client call.
type SignedBlob_Promise struct{ *capnp.Pipeline }

func (p SignedBlob_Promise) Struct() (SignedBlob, error) {
	s, err := p.Pipeline.Struct()
	return SignedBlob{s}, err
}

func (p SignedBlob_Promise) Sign() Sign_Promise {
	return Sign_Promise{Pipeline: p.Pipeline.GetPipeline(1)}
}

type Sign struct{ capnp.Struct }

// Sign_TypeID is the unique identifier for the type Sign.
const Sign_TypeID = 0x844d9464f44e810a

func NewSign(s *capnp.Segment) (Sign, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 2})
	return Sign{st}, err
}

func NewRootSign(s *capnp.Segment) (Sign, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 2})
	return Sign{st}, err
}

func ReadRootSign(msg *capnp.Message) (Sign, error) {
	root, err := msg.RootPtr()
	return Sign{root.Struct()}, err
}

func (s Sign) String() string {
	str, _ := text.Marshal(0x844d9464f44e810a, s.Struct)
	return str
}

func (s Sign) Type() SignType {
	return SignType(s.Struct.Uint16(0))
}

func (s Sign) SetType(v SignType) {
	s.Struct.SetUint16(0, uint16(v))
}

func (s Sign) Src() ([]byte, error) {
	p, err := s.Struct.Ptr(0)
	return []byte(p.Data()), err
}

func (s Sign) HasSrc() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s Sign) SetSrc(v []byte) error {
	return s.Struct.SetData(0, v)
}

func (s Sign) Signature() ([]byte, error) {
	p, err := s.Struct.Ptr(1)
	return []byte(p.Data()), err
}

func (s Sign) HasSignature() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s Sign) SetSignature(v []byte) error {
	return s.Struct.SetData(1, v)
}

func (s Sign) Timestamp() uint32 {
	return s.Struct.Uint32(4)
}

func (s Sign) SetTimestamp(v uint32) {
	s.Struct.SetUint32(4, v)
}

// Sign_List is a list of Sign.
type Sign_List struct{ capnp.List }

// NewSign creates a new list of Sign.
func NewSign_List(s *capnp.Segment, sz int32) (Sign_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 8, PointerCount: 2}, sz)
	return Sign_List{l}, err
}

func (s Sign_List) At(i int) Sign { return Sign{s.List.Struct(i)} }

func (s Sign_List) Set(i int, v Sign) error { return s.List.SetStruct(i, v.Struct) }

func (s Sign_List) String() string {
	str, _ := text.MarshalList(0x844d9464f44e810a, s.List)
	return str
}

// Sign_Promise is a wrapper for a Sign promised by a client call.
type Sign_Promise struct{ *capnp.Pipeline }

func (p Sign_Promise) Struct() (Sign, error) {
	s, err := p.Pipeline.Struct()
	return Sign{s}, err
}

type SignType uint16

// SignType_TypeID is the unique identifier for the type SignType.
const SignType_TypeID = 0xf6b5bc42e3072fc9

// Values of SignType.
const (
	SignType_none    SignType = 0
	SignType_ed25519 SignType = 1
)

// String returns the enum's constant name.
func (c SignType) String() string {
	switch c {
	case SignType_none:
		return "none"
	case SignType_ed25519:
		return "ed25519"

	default:
		return ""
	}
}

// SignTypeFromString returns the enum value with a name,
// or the zero value if there's no such value.
func SignTypeFromString(c string) SignType {
	switch c {
	case "none":
		return SignType_none
	case "ed25519":
		return SignType_ed25519

	default:
		return 0
	}
}

type SignType_List struct{ capnp.List }

func NewSignType_List(s *capnp.Segment, sz int32) (SignType_List, error) {
	l, err := capnp.NewUInt16List(s, sz)
	return SignType_List{l.List}, err
}

func (l SignType_List) At(i int) SignType {
	ul := capnp.UInt16List{List: l.List}
	return SignType(ul.At(i))
}

func (l SignType_List) Set(i int, v SignType) {
	ul := capnp.UInt16List{List: l.List}
	ul.Set(i, uint16(v))
}

const schema_99440334ec0946a0 = "x\xdal\x91?\x8b\x13A\x18\xc6\x9fg\xe6\xd6\xcd\x19" +
	"\x8e\xcd8\xdb\x0b\"\xa2\x07zw!!D\x114\x88" +
	"V\x8a\x93XZ\xb8I\x86d!\xd9\xac\xc9\x8a\x04\x04" +
	"Q\xf4\x1b\xd8X)\x82_@\xb0\xcb\x17\xf0#XX" +
	"H\x0a\x1bK\xb1\x10de\xd6\xfc\x11<\xa6\x19\x1e~" +
	"\xbc\xcf\xef\xe5=\xbc\xe2]\x13G\xde\xc19\xa0\xb3\xa0" +
	"w\"?\xf9\xec\xce\x8f\xfe\xab\xdb/`\xcad\xfe\xf6" +
	"\xe6\xee\xf7\x9a\xbc\xf1\x1a\x9e\xf0\x01\xfd\xfb\xd4sM\xfd" +
	"\xf7\xf7\x0d\xcc\xdb\xcb_\x8d\x97\xb7\xaao\xa0\xca\xff\xb1" +
	"\x9f\xf5\x07\xfd\xb5`\xbf\xe8\xc7`\xfe\xe9\xc0_\xb6\x16" +
	"\x1f\x7fB\x95\xc5\x96\x05u3|\xa7\xaf\x87\x0e\xbc\x1a" +
	"6\x90\xaf\xde\xfb|\x16\x0f\x92K\xbd(e\x92^\xee" +
	"\xc4\x83\x04wIS\x91;\xc0\x0e\x01\x15\xed\x03\xe6\xbe" +
	"\xa4\x19\x0a\x92!]f\xcf\x00\xe6\x81\xa4\x19\x09*\xc1" +
	"\x90\x02Pq\x1b0CI\x93\x09*\xc9\x90\x12P\x0f" +
	"]\x98J\x9a'\x82A6O-\x83\xad!\xc8\x00\xf4" +
	"g\xd3\x1e\xf7 \xb8\x07\x162Q\xf6h\x0a\xdaM\x96" +
	"\xc5c;\xcb\xa21\x98\xb2\x04\xc1\xd2\x8a\xfbW\xda\x9e" +
	"\xee\xb7F\x93\xaeS/m\xd4/8\xf5\xb3\x92\xe6P" +
	"P\xad\xdd/\xba\xf0\xbc\xa4\xa9\x09\x06\xdd\xd1\xa4\xbb\xee" +
	"\x09\xdcLV\xb6\x97\x01Y9\xa6\xea\x9e?OmQ" +
	"T\xac\xad\xf6\x1d\xa8v[@\x90L\x12\xfb\xd4\xf6\xab" +
	"\xf5\xfaQ\xf3O\x00\x00\x00\xff\xffV\xd5s\x1e"

func init() {
	schemas.Register(schema_99440334ec0946a0,
		0x844d9464f44e810a,
		0x9f32478537fae352,
		0xf6b5bc42e3072fc9)
}

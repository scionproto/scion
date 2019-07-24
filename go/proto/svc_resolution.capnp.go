// Code generated by capnpc-go. DO NOT EDIT.

package proto

import (
	capnp "zombiezen.com/go/capnproto2"
	text "zombiezen.com/go/capnproto2/encoding/text"
	schemas "zombiezen.com/go/capnproto2/schemas"
)

type SVCResolutionReply struct{ capnp.Struct }

// SVCResolutionReply_TypeID is the unique identifier for the type SVCResolutionReply.
const SVCResolutionReply_TypeID = 0x85b2cdeba075551b

func NewSVCResolutionReply(s *capnp.Segment) (SVCResolutionReply, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 1})
	return SVCResolutionReply{st}, err
}

func NewRootSVCResolutionReply(s *capnp.Segment) (SVCResolutionReply, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 1})
	return SVCResolutionReply{st}, err
}

func ReadRootSVCResolutionReply(msg *capnp.Message) (SVCResolutionReply, error) {
	root, err := msg.RootPtr()
	return SVCResolutionReply{root.Struct()}, err
}

func (s SVCResolutionReply) String() string {
	str, _ := text.Marshal(0x85b2cdeba075551b, s.Struct)
	return str
}

func (s SVCResolutionReply) Transports() (Transport_List, error) {
	p, err := s.Struct.Ptr(0)
	return Transport_List{List: p.List()}, err
}

func (s SVCResolutionReply) HasTransports() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s SVCResolutionReply) SetTransports(v Transport_List) error {
	return s.Struct.SetPtr(0, v.List.ToPtr())
}

// NewTransports sets the transports field to a newly
// allocated Transport_List, preferring placement in s's segment.
func (s SVCResolutionReply) NewTransports(n int32) (Transport_List, error) {
	l, err := NewTransport_List(s.Struct.Segment(), n)
	if err != nil {
		return Transport_List{}, err
	}
	err = s.Struct.SetPtr(0, l.List.ToPtr())
	return l, err
}

// SVCResolutionReply_List is a list of SVCResolutionReply.
type SVCResolutionReply_List struct{ capnp.List }

// NewSVCResolutionReply creates a new list of SVCResolutionReply.
func NewSVCResolutionReply_List(s *capnp.Segment, sz int32) (SVCResolutionReply_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 1}, sz)
	return SVCResolutionReply_List{l}, err
}

func (s SVCResolutionReply_List) At(i int) SVCResolutionReply {
	return SVCResolutionReply{s.List.Struct(i)}
}

func (s SVCResolutionReply_List) Set(i int, v SVCResolutionReply) error {
	return s.List.SetStruct(i, v.Struct)
}

func (s SVCResolutionReply_List) String() string {
	str, _ := text.MarshalList(0x85b2cdeba075551b, s.List)
	return str
}

// SVCResolutionReply_Promise is a wrapper for a SVCResolutionReply promised by a client call.
type SVCResolutionReply_Promise struct{ *capnp.Pipeline }

func (p SVCResolutionReply_Promise) Struct() (SVCResolutionReply, error) {
	s, err := p.Pipeline.Struct()
	return SVCResolutionReply{s}, err
}

type Transport struct{ capnp.Struct }

// Transport_TypeID is the unique identifier for the type Transport.
const Transport_TypeID = 0xdec7fa6a5148fde5

func NewTransport(s *capnp.Segment) (Transport, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return Transport{st}, err
}

func NewRootTransport(s *capnp.Segment) (Transport, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2})
	return Transport{st}, err
}

func ReadRootTransport(msg *capnp.Message) (Transport, error) {
	root, err := msg.RootPtr()
	return Transport{root.Struct()}, err
}

func (s Transport) String() string {
	str, _ := text.Marshal(0xdec7fa6a5148fde5, s.Struct)
	return str
}

func (s Transport) Key() (string, error) {
	p, err := s.Struct.Ptr(0)
	return p.Text(), err
}

func (s Transport) HasKey() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s Transport) KeyBytes() ([]byte, error) {
	p, err := s.Struct.Ptr(0)
	return p.TextBytes(), err
}

func (s Transport) SetKey(v string) error {
	return s.Struct.SetText(0, v)
}

func (s Transport) Value() (string, error) {
	p, err := s.Struct.Ptr(1)
	return p.Text(), err
}

func (s Transport) HasValue() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s Transport) ValueBytes() ([]byte, error) {
	p, err := s.Struct.Ptr(1)
	return p.TextBytes(), err
}

func (s Transport) SetValue(v string) error {
	return s.Struct.SetText(1, v)
}

// Transport_List is a list of Transport.
type Transport_List struct{ capnp.List }

// NewTransport creates a new list of Transport.
func NewTransport_List(s *capnp.Segment, sz int32) (Transport_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 2}, sz)
	return Transport_List{l}, err
}

func (s Transport_List) At(i int) Transport { return Transport{s.List.Struct(i)} }

func (s Transport_List) Set(i int, v Transport) error { return s.List.SetStruct(i, v.Struct) }

func (s Transport_List) String() string {
	str, _ := text.MarshalList(0xdec7fa6a5148fde5, s.List)
	return str
}

// Transport_Promise is a wrapper for a Transport promised by a client call.
type Transport_Promise struct{ *capnp.Pipeline }

func (p Transport_Promise) Struct() (Transport, error) {
	s, err := p.Pipeline.Struct()
	return Transport{s}, err
}

const schema_a52f74a5947eb3b7 = "x\xda2\xe0`u`2d\xd5Wc`\x08\xde\xc3" +
	"\xc8\xca\xf6_:\xb4t\xc1\xeb\xb3\x9bZ\x19\x04E\x19" +
	"\xffo\xdf\\7ei\x89\xfeR\x06VFv\x06\x06" +
	"\xe3\xbfBN\x8c\xc2\xbc\xc2\xec\x0c\x0c\xc2\x9c\xc2\xf6\x0c" +
	"\x8c\xff\x9f\xfe\xf5\x08\xcc\xfau\xfc\x1e\x9ab&\x90\x0a" +
	"[\xe1_\xc2\x9e`\xb5\xae\xc2\xe5\x0c\xff\xa1p\xc3\xff" +
	"\xe2\xb2\xe4\xf8\xa2\xd4\xe2|\x96\x9c\xd2\x92\xcc\xfc<\xbd" +
	"\xe4\xc4\x82\xbc\x02\xab\xe00\xe7\xa0\xd4\xe2|\x88XP" +
	"jAN%C\x00#c \x0b3\x0b\x03\x03\x0b#" +
	"\x03\x83 o\x14\x03C \x0f3c\xa0\x06\x13\xe3\xff" +
	"\x92\xa2\xc4\xbc\xe2\x82\xfc\"\x06\xe6\x92bF>\x06\xc6" +
	"\x00fFF\x01\x84k\x18\x18A\x82p\x9b\x98Pl" +
	"\x0a)J\xb4\x07k.\x01Y\xc0\x01\xb7@S\x89\x81" +
	"!P\x85\x991\xd0\x80\x89Q\x90\x91Q\x84\x11$\xa8" +
	"k\xc4\xc0\x10\xa8\xc1\xcc\x18h\xc2\xc4\xc8\x9e\x9dZ\xc9" +
	"\xc8\xc3\xc0\xc4\xc8\xc3\xc0(_\x96\x98S\x9a\x0a\xe3\x01" +
	"\x02\x00\x00\xff\xff\x0e\xc8V\xf9"

func init() {
	schemas.Register(schema_a52f74a5947eb3b7,
		0x85b2cdeba075551b,
		0xdec7fa6a5148fde5)
}

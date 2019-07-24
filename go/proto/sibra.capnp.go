// Code generated by capnpc-go. DO NOT EDIT.

package proto

import (
	capnp "zombiezen.com/go/capnproto2"
	text "zombiezen.com/go/capnproto2/encoding/text"
	schemas "zombiezen.com/go/capnproto2/schemas"
)

type SibraPCBExt struct{ capnp.Struct }

// SibraPCBExt_TypeID is the unique identifier for the type SibraPCBExt.
const SibraPCBExt_TypeID = 0xb8fde9b959e9608d

func NewSibraPCBExt(s *capnp.Segment) (SibraPCBExt, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 3})
	return SibraPCBExt{st}, err
}

func NewRootSibraPCBExt(s *capnp.Segment) (SibraPCBExt, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 8, PointerCount: 3})
	return SibraPCBExt{st}, err
}

func ReadRootSibraPCBExt(msg *capnp.Message) (SibraPCBExt, error) {
	root, err := msg.RootPtr()
	return SibraPCBExt{root.Struct()}, err
}

func (s SibraPCBExt) String() string {
	str, _ := text.Marshal(0xb8fde9b959e9608d, s.Struct)
	return str
}

func (s SibraPCBExt) Id() ([]byte, error) {
	p, err := s.Struct.Ptr(0)
	return []byte(p.Data()), err
}

func (s SibraPCBExt) HasId() bool {
	p, err := s.Struct.Ptr(0)
	return p.IsValid() || err != nil
}

func (s SibraPCBExt) SetId(v []byte) error {
	return s.Struct.SetData(0, v)
}

func (s SibraPCBExt) Info() ([]byte, error) {
	p, err := s.Struct.Ptr(1)
	return []byte(p.Data()), err
}

func (s SibraPCBExt) HasInfo() bool {
	p, err := s.Struct.Ptr(1)
	return p.IsValid() || err != nil
}

func (s SibraPCBExt) SetInfo(v []byte) error {
	return s.Struct.SetData(1, v)
}

func (s SibraPCBExt) Up() bool {
	return s.Struct.Bit(0)
}

func (s SibraPCBExt) SetUp(v bool) {
	s.Struct.SetBit(0, v)
}

func (s SibraPCBExt) Sofs() (capnp.DataList, error) {
	p, err := s.Struct.Ptr(2)
	return capnp.DataList{List: p.List()}, err
}

func (s SibraPCBExt) HasSofs() bool {
	p, err := s.Struct.Ptr(2)
	return p.IsValid() || err != nil
}

func (s SibraPCBExt) SetSofs(v capnp.DataList) error {
	return s.Struct.SetPtr(2, v.List.ToPtr())
}

// NewSofs sets the sofs field to a newly
// allocated capnp.DataList, preferring placement in s's segment.
func (s SibraPCBExt) NewSofs(n int32) (capnp.DataList, error) {
	l, err := capnp.NewDataList(s.Struct.Segment(), n)
	if err != nil {
		return capnp.DataList{}, err
	}
	err = s.Struct.SetPtr(2, l.List.ToPtr())
	return l, err
}

// SibraPCBExt_List is a list of SibraPCBExt.
type SibraPCBExt_List struct{ capnp.List }

// NewSibraPCBExt creates a new list of SibraPCBExt.
func NewSibraPCBExt_List(s *capnp.Segment, sz int32) (SibraPCBExt_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 8, PointerCount: 3}, sz)
	return SibraPCBExt_List{l}, err
}

func (s SibraPCBExt_List) At(i int) SibraPCBExt { return SibraPCBExt{s.List.Struct(i)} }

func (s SibraPCBExt_List) Set(i int, v SibraPCBExt) error { return s.List.SetStruct(i, v.Struct) }

func (s SibraPCBExt_List) String() string {
	str, _ := text.MarshalList(0xb8fde9b959e9608d, s.List)
	return str
}

// SibraPCBExt_Promise is a wrapper for a SibraPCBExt promised by a client call.
type SibraPCBExt_Promise struct{ *capnp.Pipeline }

func (p SibraPCBExt_Promise) Struct() (SibraPCBExt, error) {
	s, err := p.Pipeline.Struct()
	return SibraPCBExt{s}, err
}

type SibraPayload struct{ capnp.Struct }

// SibraPayload_TypeID is the unique identifier for the type SibraPayload.
const SibraPayload_TypeID = 0xf231c8f55f84c390

func NewSibraPayload(s *capnp.Segment) (SibraPayload, error) {
	st, err := capnp.NewStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 0})
	return SibraPayload{st}, err
}

func NewRootSibraPayload(s *capnp.Segment) (SibraPayload, error) {
	st, err := capnp.NewRootStruct(s, capnp.ObjectSize{DataSize: 0, PointerCount: 0})
	return SibraPayload{st}, err
}

func ReadRootSibraPayload(msg *capnp.Message) (SibraPayload, error) {
	root, err := msg.RootPtr()
	return SibraPayload{root.Struct()}, err
}

func (s SibraPayload) String() string {
	str, _ := text.Marshal(0xf231c8f55f84c390, s.Struct)
	return str
}

// SibraPayload_List is a list of SibraPayload.
type SibraPayload_List struct{ capnp.List }

// NewSibraPayload creates a new list of SibraPayload.
func NewSibraPayload_List(s *capnp.Segment, sz int32) (SibraPayload_List, error) {
	l, err := capnp.NewCompositeList(s, capnp.ObjectSize{DataSize: 0, PointerCount: 0}, sz)
	return SibraPayload_List{l}, err
}

func (s SibraPayload_List) At(i int) SibraPayload { return SibraPayload{s.List.Struct(i)} }

func (s SibraPayload_List) Set(i int, v SibraPayload) error { return s.List.SetStruct(i, v.Struct) }

func (s SibraPayload_List) String() string {
	str, _ := text.MarshalList(0xf231c8f55f84c390, s.List)
	return str
}

// SibraPayload_Promise is a wrapper for a SibraPayload promised by a client call.
type SibraPayload_Promise struct{ *capnp.Pipeline }

func (p SibraPayload_Promise) Struct() (SibraPayload, error) {
	s, err := p.Pipeline.Struct()
	return SibraPayload{s}, err
}

const schema_d7ac72be29310d11 = "x\xdal\xce\xb1J\xc3P\x14\x06\xe0\xff?\xa7\xb1K" +
	"\xd3z\xbd\x99|\x00A\x075\xab\x93(\xee\xb9t\x12" +
	"\x04\x1b\x8d\xa5\x81\xda\x84FA\xf7\xae\x82\x0f\xe2\xe4\xa4" +
	" \x0e\xba\x88/\xe0\x13\x88tTp,\x91+\x0a\x0e" +
	"r\x96\xf3\x9f\xf3\x0d\xff\xba\x0d6%\x0e\xd6\x96\x80\xee" +
	"\x1d\x83\xb9\xfa\xa27\xdd\xbd\x9d\xcen\xe0Zdm\xc2" +
	"x\xf9~|\xf5\x82@\x9b\x80\x9d-<\xd8\xc0\xfa\x8d" +
	"\xf6\x0d\xac/\x1f'\xfb\x9fO\xf1\x07L\xeb\x8fmx" +
	"\xf0j\x9f\xed\xbbm\xa2\xfe\x99\xeb\xba\xca\x0f\xc6\xe9\xea" +
	"a*\xe5\xa8\xdc\xe8\xfa\x90lo\xed\x9c\x9d !\xdd" +
	"\xbc6\x80\x06\x01\x93.\x02nO\xe9\x06BCF\xf4" +
	"\xc7\xa3\x15\xc0\xf5\x94n(\xa4D\x14\xc0\xe4\x1efJ" +
	"W\x0a\x8dJD\x05\xcc\xb1\x87\x03\xa5\x9b\x085\xcf\x18" +
	"B\x18\x82\x9d|\xd4/~\x83\x9e\x96$\x84\x04;U" +
	"\xd1\xaf\xd8\x06\x13\xe5\xf7\xbb\x0d\xfeW4=\x1f\x16i" +
	"\x06_\xf5+\x00\x00\xff\xff\xa7\xaaF*"

func init() {
	schemas.Register(schema_d7ac72be29310d11,
		0xb8fde9b959e9608d,
		0xf231c8f55f84c390)
}

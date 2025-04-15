// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v6.30.1
// source: proto/discovery/v1/discovery.proto

package discovery

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type GatewaysRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GatewaysRequest) Reset() {
	*x = GatewaysRequest{}
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GatewaysRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GatewaysRequest) ProtoMessage() {}

func (x *GatewaysRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GatewaysRequest.ProtoReflect.Descriptor instead.
func (*GatewaysRequest) Descriptor() ([]byte, []int) {
	return file_proto_discovery_v1_discovery_proto_rawDescGZIP(), []int{0}
}

type GatewaysResponse struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Gateways      []*Gateway             `protobuf:"bytes,1,rep,name=gateways,proto3" json:"gateways,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *GatewaysResponse) Reset() {
	*x = GatewaysResponse{}
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *GatewaysResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GatewaysResponse) ProtoMessage() {}

func (x *GatewaysResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GatewaysResponse.ProtoReflect.Descriptor instead.
func (*GatewaysResponse) Descriptor() ([]byte, []int) {
	return file_proto_discovery_v1_discovery_proto_rawDescGZIP(), []int{1}
}

func (x *GatewaysResponse) GetGateways() []*Gateway {
	if x != nil {
		return x.Gateways
	}
	return nil
}

type Gateway struct {
	state           protoimpl.MessageState `protogen:"open.v1"`
	ControlAddress  string                 `protobuf:"bytes,1,opt,name=control_address,json=controlAddress,proto3" json:"control_address,omitempty"`
	DataAddress     string                 `protobuf:"bytes,2,opt,name=data_address,json=dataAddress,proto3" json:"data_address,omitempty"`
	ProbeAddress    string                 `protobuf:"bytes,3,opt,name=probe_address,json=probeAddress,proto3" json:"probe_address,omitempty"`
	AllowInterfaces []uint64               `protobuf:"varint,4,rep,packed,name=allow_interfaces,json=allowInterfaces,proto3" json:"allow_interfaces,omitempty"`
	unknownFields   protoimpl.UnknownFields
	sizeCache       protoimpl.SizeCache
}

func (x *Gateway) Reset() {
	*x = Gateway{}
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Gateway) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Gateway) ProtoMessage() {}

func (x *Gateway) ProtoReflect() protoreflect.Message {
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Gateway.ProtoReflect.Descriptor instead.
func (*Gateway) Descriptor() ([]byte, []int) {
	return file_proto_discovery_v1_discovery_proto_rawDescGZIP(), []int{2}
}

func (x *Gateway) GetControlAddress() string {
	if x != nil {
		return x.ControlAddress
	}
	return ""
}

func (x *Gateway) GetDataAddress() string {
	if x != nil {
		return x.DataAddress
	}
	return ""
}

func (x *Gateway) GetProbeAddress() string {
	if x != nil {
		return x.ProbeAddress
	}
	return ""
}

func (x *Gateway) GetAllowInterfaces() []uint64 {
	if x != nil {
		return x.AllowInterfaces
	}
	return nil
}

type HiddenSegmentServicesRequest struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HiddenSegmentServicesRequest) Reset() {
	*x = HiddenSegmentServicesRequest{}
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HiddenSegmentServicesRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HiddenSegmentServicesRequest) ProtoMessage() {}

func (x *HiddenSegmentServicesRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HiddenSegmentServicesRequest.ProtoReflect.Descriptor instead.
func (*HiddenSegmentServicesRequest) Descriptor() ([]byte, []int) {
	return file_proto_discovery_v1_discovery_proto_rawDescGZIP(), []int{3}
}

type HiddenSegmentServicesResponse struct {
	state         protoimpl.MessageState             `protogen:"open.v1"`
	Lookup        []*HiddenSegmentLookupServer       `protobuf:"bytes,1,rep,name=lookup,proto3" json:"lookup,omitempty"`
	Registration  []*HiddenSegmentRegistrationServer `protobuf:"bytes,2,rep,name=registration,proto3" json:"registration,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HiddenSegmentServicesResponse) Reset() {
	*x = HiddenSegmentServicesResponse{}
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HiddenSegmentServicesResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HiddenSegmentServicesResponse) ProtoMessage() {}

func (x *HiddenSegmentServicesResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HiddenSegmentServicesResponse.ProtoReflect.Descriptor instead.
func (*HiddenSegmentServicesResponse) Descriptor() ([]byte, []int) {
	return file_proto_discovery_v1_discovery_proto_rawDescGZIP(), []int{4}
}

func (x *HiddenSegmentServicesResponse) GetLookup() []*HiddenSegmentLookupServer {
	if x != nil {
		return x.Lookup
	}
	return nil
}

func (x *HiddenSegmentServicesResponse) GetRegistration() []*HiddenSegmentRegistrationServer {
	if x != nil {
		return x.Registration
	}
	return nil
}

type HiddenSegmentLookupServer struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Address       string                 `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HiddenSegmentLookupServer) Reset() {
	*x = HiddenSegmentLookupServer{}
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HiddenSegmentLookupServer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HiddenSegmentLookupServer) ProtoMessage() {}

func (x *HiddenSegmentLookupServer) ProtoReflect() protoreflect.Message {
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HiddenSegmentLookupServer.ProtoReflect.Descriptor instead.
func (*HiddenSegmentLookupServer) Descriptor() ([]byte, []int) {
	return file_proto_discovery_v1_discovery_proto_rawDescGZIP(), []int{5}
}

func (x *HiddenSegmentLookupServer) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

type HiddenSegmentRegistrationServer struct {
	state         protoimpl.MessageState `protogen:"open.v1"`
	Address       string                 `protobuf:"bytes,1,opt,name=address,proto3" json:"address,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *HiddenSegmentRegistrationServer) Reset() {
	*x = HiddenSegmentRegistrationServer{}
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[6]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *HiddenSegmentRegistrationServer) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HiddenSegmentRegistrationServer) ProtoMessage() {}

func (x *HiddenSegmentRegistrationServer) ProtoReflect() protoreflect.Message {
	mi := &file_proto_discovery_v1_discovery_proto_msgTypes[6]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HiddenSegmentRegistrationServer.ProtoReflect.Descriptor instead.
func (*HiddenSegmentRegistrationServer) Descriptor() ([]byte, []int) {
	return file_proto_discovery_v1_discovery_proto_rawDescGZIP(), []int{6}
}

func (x *HiddenSegmentRegistrationServer) GetAddress() string {
	if x != nil {
		return x.Address
	}
	return ""
}

var File_proto_discovery_v1_discovery_proto protoreflect.FileDescriptor

const file_proto_discovery_v1_discovery_proto_rawDesc = "" +
	"\n" +
	"\"proto/discovery/v1/discovery.proto\x12\x12proto.discovery.v1\"\x11\n" +
	"\x0fGatewaysRequest\"K\n" +
	"\x10GatewaysResponse\x127\n" +
	"\bgateways\x18\x01 \x03(\v2\x1b.proto.discovery.v1.GatewayR\bgateways\"\xa5\x01\n" +
	"\aGateway\x12'\n" +
	"\x0fcontrol_address\x18\x01 \x01(\tR\x0econtrolAddress\x12!\n" +
	"\fdata_address\x18\x02 \x01(\tR\vdataAddress\x12#\n" +
	"\rprobe_address\x18\x03 \x01(\tR\fprobeAddress\x12)\n" +
	"\x10allow_interfaces\x18\x04 \x03(\x04R\x0fallowInterfaces\"\x1e\n" +
	"\x1cHiddenSegmentServicesRequest\"\xbf\x01\n" +
	"\x1dHiddenSegmentServicesResponse\x12E\n" +
	"\x06lookup\x18\x01 \x03(\v2-.proto.discovery.v1.HiddenSegmentLookupServerR\x06lookup\x12W\n" +
	"\fregistration\x18\x02 \x03(\v23.proto.discovery.v1.HiddenSegmentRegistrationServerR\fregistration\"5\n" +
	"\x19HiddenSegmentLookupServer\x12\x18\n" +
	"\aaddress\x18\x01 \x01(\tR\aaddress\";\n" +
	"\x1fHiddenSegmentRegistrationServer\x12\x18\n" +
	"\aaddress\x18\x01 \x01(\tR\aaddress2\xeb\x01\n" +
	"\x10DiscoveryService\x12W\n" +
	"\bGateways\x12#.proto.discovery.v1.GatewaysRequest\x1a$.proto.discovery.v1.GatewaysResponse\"\x00\x12~\n" +
	"\x15HiddenSegmentServices\x120.proto.discovery.v1.HiddenSegmentServicesRequest\x1a1.proto.discovery.v1.HiddenSegmentServicesResponse\"\x00B1Z/github.com/scionproto/scion/pkg/proto/discoveryb\x06proto3"

var (
	file_proto_discovery_v1_discovery_proto_rawDescOnce sync.Once
	file_proto_discovery_v1_discovery_proto_rawDescData []byte
)

func file_proto_discovery_v1_discovery_proto_rawDescGZIP() []byte {
	file_proto_discovery_v1_discovery_proto_rawDescOnce.Do(func() {
		file_proto_discovery_v1_discovery_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_proto_discovery_v1_discovery_proto_rawDesc), len(file_proto_discovery_v1_discovery_proto_rawDesc)))
	})
	return file_proto_discovery_v1_discovery_proto_rawDescData
}

var file_proto_discovery_v1_discovery_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_proto_discovery_v1_discovery_proto_goTypes = []any{
	(*GatewaysRequest)(nil),                 // 0: proto.discovery.v1.GatewaysRequest
	(*GatewaysResponse)(nil),                // 1: proto.discovery.v1.GatewaysResponse
	(*Gateway)(nil),                         // 2: proto.discovery.v1.Gateway
	(*HiddenSegmentServicesRequest)(nil),    // 3: proto.discovery.v1.HiddenSegmentServicesRequest
	(*HiddenSegmentServicesResponse)(nil),   // 4: proto.discovery.v1.HiddenSegmentServicesResponse
	(*HiddenSegmentLookupServer)(nil),       // 5: proto.discovery.v1.HiddenSegmentLookupServer
	(*HiddenSegmentRegistrationServer)(nil), // 6: proto.discovery.v1.HiddenSegmentRegistrationServer
}
var file_proto_discovery_v1_discovery_proto_depIdxs = []int32{
	2, // 0: proto.discovery.v1.GatewaysResponse.gateways:type_name -> proto.discovery.v1.Gateway
	5, // 1: proto.discovery.v1.HiddenSegmentServicesResponse.lookup:type_name -> proto.discovery.v1.HiddenSegmentLookupServer
	6, // 2: proto.discovery.v1.HiddenSegmentServicesResponse.registration:type_name -> proto.discovery.v1.HiddenSegmentRegistrationServer
	0, // 3: proto.discovery.v1.DiscoveryService.Gateways:input_type -> proto.discovery.v1.GatewaysRequest
	3, // 4: proto.discovery.v1.DiscoveryService.HiddenSegmentServices:input_type -> proto.discovery.v1.HiddenSegmentServicesRequest
	1, // 5: proto.discovery.v1.DiscoveryService.Gateways:output_type -> proto.discovery.v1.GatewaysResponse
	4, // 6: proto.discovery.v1.DiscoveryService.HiddenSegmentServices:output_type -> proto.discovery.v1.HiddenSegmentServicesResponse
	5, // [5:7] is the sub-list for method output_type
	3, // [3:5] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_proto_discovery_v1_discovery_proto_init() }
func file_proto_discovery_v1_discovery_proto_init() {
	if File_proto_discovery_v1_discovery_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_proto_discovery_v1_discovery_proto_rawDesc), len(file_proto_discovery_v1_discovery_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   7,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_discovery_v1_discovery_proto_goTypes,
		DependencyIndexes: file_proto_discovery_v1_discovery_proto_depIdxs,
		MessageInfos:      file_proto_discovery_v1_discovery_proto_msgTypes,
	}.Build()
	File_proto_discovery_v1_discovery_proto = out.File
	file_proto_discovery_v1_discovery_proto_goTypes = nil
	file_proto_discovery_v1_discovery_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// DiscoveryServiceClient is the client API for DiscoveryService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type DiscoveryServiceClient interface {
	Gateways(ctx context.Context, in *GatewaysRequest, opts ...grpc.CallOption) (*GatewaysResponse, error)
	HiddenSegmentServices(ctx context.Context, in *HiddenSegmentServicesRequest, opts ...grpc.CallOption) (*HiddenSegmentServicesResponse, error)
}

type discoveryServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewDiscoveryServiceClient(cc grpc.ClientConnInterface) DiscoveryServiceClient {
	return &discoveryServiceClient{cc}
}

func (c *discoveryServiceClient) Gateways(ctx context.Context, in *GatewaysRequest, opts ...grpc.CallOption) (*GatewaysResponse, error) {
	out := new(GatewaysResponse)
	err := c.cc.Invoke(ctx, "/proto.discovery.v1.DiscoveryService/Gateways", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *discoveryServiceClient) HiddenSegmentServices(ctx context.Context, in *HiddenSegmentServicesRequest, opts ...grpc.CallOption) (*HiddenSegmentServicesResponse, error) {
	out := new(HiddenSegmentServicesResponse)
	err := c.cc.Invoke(ctx, "/proto.discovery.v1.DiscoveryService/HiddenSegmentServices", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DiscoveryServiceServer is the server API for DiscoveryService service.
type DiscoveryServiceServer interface {
	Gateways(context.Context, *GatewaysRequest) (*GatewaysResponse, error)
	HiddenSegmentServices(context.Context, *HiddenSegmentServicesRequest) (*HiddenSegmentServicesResponse, error)
}

// UnimplementedDiscoveryServiceServer can be embedded to have forward compatible implementations.
type UnimplementedDiscoveryServiceServer struct {
}

func (*UnimplementedDiscoveryServiceServer) Gateways(context.Context, *GatewaysRequest) (*GatewaysResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Gateways not implemented")
}
func (*UnimplementedDiscoveryServiceServer) HiddenSegmentServices(context.Context, *HiddenSegmentServicesRequest) (*HiddenSegmentServicesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HiddenSegmentServices not implemented")
}

func RegisterDiscoveryServiceServer(s *grpc.Server, srv DiscoveryServiceServer) {
	s.RegisterService(&_DiscoveryService_serviceDesc, srv)
}

func _DiscoveryService_Gateways_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GatewaysRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DiscoveryServiceServer).Gateways(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.discovery.v1.DiscoveryService/Gateways",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DiscoveryServiceServer).Gateways(ctx, req.(*GatewaysRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _DiscoveryService_HiddenSegmentServices_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HiddenSegmentServicesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(DiscoveryServiceServer).HiddenSegmentServices(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.discovery.v1.DiscoveryService/HiddenSegmentServices",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(DiscoveryServiceServer).HiddenSegmentServices(ctx, req.(*HiddenSegmentServicesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _DiscoveryService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.discovery.v1.DiscoveryService",
	HandlerType: (*DiscoveryServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Gateways",
			Handler:    _DiscoveryService_Gateways_Handler,
		},
		{
			MethodName: "HiddenSegmentServices",
			Handler:    _DiscoveryService_HiddenSegmentServices_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/discovery/v1/discovery.proto",
}

// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.35.1
// 	protoc        v5.28.2
// source: things/v1/things.proto

package v1

import (
	v1 "github.com/absmach/supermq/internal/grpc/common/v1"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AuthnReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ThingId  string `protobuf:"bytes,1,opt,name=thing_id,json=thingId,proto3" json:"thing_id,omitempty"`
	ThingKey string `protobuf:"bytes,2,opt,name=thing_key,json=thingKey,proto3" json:"thing_key,omitempty"`
}

func (x *AuthnReq) Reset() {
	*x = AuthnReq{}
	mi := &file_things_v1_things_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AuthnReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthnReq) ProtoMessage() {}

func (x *AuthnReq) ProtoReflect() protoreflect.Message {
	mi := &file_things_v1_things_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthnReq.ProtoReflect.Descriptor instead.
func (*AuthnReq) Descriptor() ([]byte, []int) {
	return file_things_v1_things_proto_rawDescGZIP(), []int{0}
}

func (x *AuthnReq) GetThingId() string {
	if x != nil {
		return x.ThingId
	}
	return ""
}

func (x *AuthnReq) GetThingKey() string {
	if x != nil {
		return x.ThingKey
	}
	return ""
}

type AuthnRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Authenticated bool   `protobuf:"varint,1,opt,name=authenticated,proto3" json:"authenticated,omitempty"`
	Id            string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *AuthnRes) Reset() {
	*x = AuthnRes{}
	mi := &file_things_v1_things_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *AuthnRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AuthnRes) ProtoMessage() {}

func (x *AuthnRes) ProtoReflect() protoreflect.Message {
	mi := &file_things_v1_things_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AuthnRes.ProtoReflect.Descriptor instead.
func (*AuthnRes) Descriptor() ([]byte, []int) {
	return file_things_v1_things_proto_rawDescGZIP(), []int{1}
}

func (x *AuthnRes) GetAuthenticated() bool {
	if x != nil {
		return x.Authenticated
	}
	return false
}

func (x *AuthnRes) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type RemoveChannelConnectionsReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ChannelId string `protobuf:"bytes,1,opt,name=channel_id,json=channelId,proto3" json:"channel_id,omitempty"`
}

func (x *RemoveChannelConnectionsReq) Reset() {
	*x = RemoveChannelConnectionsReq{}
	mi := &file_things_v1_things_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RemoveChannelConnectionsReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RemoveChannelConnectionsReq) ProtoMessage() {}

func (x *RemoveChannelConnectionsReq) ProtoReflect() protoreflect.Message {
	mi := &file_things_v1_things_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RemoveChannelConnectionsReq.ProtoReflect.Descriptor instead.
func (*RemoveChannelConnectionsReq) Descriptor() ([]byte, []int) {
	return file_things_v1_things_proto_rawDescGZIP(), []int{2}
}

func (x *RemoveChannelConnectionsReq) GetChannelId() string {
	if x != nil {
		return x.ChannelId
	}
	return ""
}

type RemoveChannelConnectionsRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RemoveChannelConnectionsRes) Reset() {
	*x = RemoveChannelConnectionsRes{}
	mi := &file_things_v1_things_proto_msgTypes[3]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *RemoveChannelConnectionsRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RemoveChannelConnectionsRes) ProtoMessage() {}

func (x *RemoveChannelConnectionsRes) ProtoReflect() protoreflect.Message {
	mi := &file_things_v1_things_proto_msgTypes[3]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RemoveChannelConnectionsRes.ProtoReflect.Descriptor instead.
func (*RemoveChannelConnectionsRes) Descriptor() ([]byte, []int) {
	return file_things_v1_things_proto_rawDescGZIP(), []int{3}
}

type UnsetParentGroupFromThingsReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ParentGroupId string `protobuf:"bytes,1,opt,name=parent_group_id,json=parentGroupId,proto3" json:"parent_group_id,omitempty"`
}

func (x *UnsetParentGroupFromThingsReq) Reset() {
	*x = UnsetParentGroupFromThingsReq{}
	mi := &file_things_v1_things_proto_msgTypes[4]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UnsetParentGroupFromThingsReq) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnsetParentGroupFromThingsReq) ProtoMessage() {}

func (x *UnsetParentGroupFromThingsReq) ProtoReflect() protoreflect.Message {
	mi := &file_things_v1_things_proto_msgTypes[4]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnsetParentGroupFromThingsReq.ProtoReflect.Descriptor instead.
func (*UnsetParentGroupFromThingsReq) Descriptor() ([]byte, []int) {
	return file_things_v1_things_proto_rawDescGZIP(), []int{4}
}

func (x *UnsetParentGroupFromThingsReq) GetParentGroupId() string {
	if x != nil {
		return x.ParentGroupId
	}
	return ""
}

type UnsetParentGroupFromThingsRes struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *UnsetParentGroupFromThingsRes) Reset() {
	*x = UnsetParentGroupFromThingsRes{}
	mi := &file_things_v1_things_proto_msgTypes[5]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *UnsetParentGroupFromThingsRes) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*UnsetParentGroupFromThingsRes) ProtoMessage() {}

func (x *UnsetParentGroupFromThingsRes) ProtoReflect() protoreflect.Message {
	mi := &file_things_v1_things_proto_msgTypes[5]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use UnsetParentGroupFromThingsRes.ProtoReflect.Descriptor instead.
func (*UnsetParentGroupFromThingsRes) Descriptor() ([]byte, []int) {
	return file_things_v1_things_proto_rawDescGZIP(), []int{5}
}

var File_things_v1_things_proto protoreflect.FileDescriptor

var file_things_v1_things_proto_rawDesc = []byte{
	0x0a, 0x16, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2f, 0x76, 0x31, 0x2f, 0x74, 0x68, 0x69, 0x6e,
	0x67, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x09, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73,
	0x2e, 0x76, 0x31, 0x1a, 0x16, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x76, 0x31, 0x2f, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x42, 0x0a, 0x08, 0x41,
	0x75, 0x74, 0x68, 0x6e, 0x52, 0x65, 0x71, 0x12, 0x19, 0x0a, 0x08, 0x74, 0x68, 0x69, 0x6e, 0x67,
	0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x74, 0x68, 0x69, 0x6e, 0x67,
	0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x6b, 0x65, 0x79, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x4b, 0x65, 0x79, 0x22,
	0x40, 0x0a, 0x08, 0x41, 0x75, 0x74, 0x68, 0x6e, 0x52, 0x65, 0x73, 0x12, 0x24, 0x0a, 0x0d, 0x61,
	0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x0d, 0x61, 0x75, 0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65,
	0x64, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69,
	0x64, 0x22, 0x3c, 0x0a, 0x1b, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x68, 0x61, 0x6e, 0x6e,
	0x65, 0x6c, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71,
	0x12, 0x1d, 0x0a, 0x0a, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x5f, 0x69, 0x64, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x49, 0x64, 0x22,
	0x1d, 0x0a, 0x1b, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c,
	0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x22, 0x47,
	0x0a, 0x1d, 0x55, 0x6e, 0x73, 0x65, 0x74, 0x50, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x47, 0x72, 0x6f,
	0x75, 0x70, 0x46, 0x72, 0x6f, 0x6d, 0x54, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x52, 0x65, 0x71, 0x12,
	0x26, 0x0a, 0x0f, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x5f, 0x67, 0x72, 0x6f, 0x75, 0x70, 0x5f,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x70, 0x61, 0x72, 0x65, 0x6e, 0x74,
	0x47, 0x72, 0x6f, 0x75, 0x70, 0x49, 0x64, 0x22, 0x1f, 0x0a, 0x1d, 0x55, 0x6e, 0x73, 0x65, 0x74,
	0x50, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x46, 0x72, 0x6f, 0x6d, 0x54,
	0x68, 0x69, 0x6e, 0x67, 0x73, 0x52, 0x65, 0x73, 0x32, 0xfc, 0x04, 0x0a, 0x0d, 0x54, 0x68, 0x69,
	0x6e, 0x67, 0x73, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x3a, 0x0a, 0x0c, 0x41, 0x75,
	0x74, 0x68, 0x65, 0x6e, 0x74, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x13, 0x2e, 0x74, 0x68, 0x69,
	0x6e, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68, 0x6e, 0x52, 0x65, 0x71, 0x1a,
	0x13, 0x2e, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x75, 0x74, 0x68,
	0x6e, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x4e, 0x0a, 0x0e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65,
	0x76, 0x65, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x79, 0x12, 0x1c, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x45, 0x6e, 0x74,
	0x69, 0x74, 0x79, 0x52, 0x65, 0x71, 0x1a, 0x1c, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e,
	0x76, 0x31, 0x2e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x45, 0x6e, 0x74, 0x69, 0x74,
	0x79, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x54, 0x0a, 0x10, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65,
	0x76, 0x65, 0x45, 0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x12, 0x1e, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x45,
	0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x52, 0x65, 0x71, 0x1a, 0x1e, 0x2e, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x74, 0x72, 0x69, 0x65, 0x76, 0x65, 0x45,
	0x6e, 0x74, 0x69, 0x74, 0x69, 0x65, 0x73, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x4e, 0x0a, 0x0e,
	0x41, 0x64, 0x64, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x1c,
	0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x64, 0x64, 0x43, 0x6f,
	0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x1a, 0x1c, 0x2e, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x41, 0x64, 0x64, 0x43, 0x6f, 0x6e, 0x6e,
	0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x57, 0x0a, 0x11,
	0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x12, 0x1f, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65,
	0x6d, 0x6f, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52,
	0x65, 0x71, 0x1a, 0x1f, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x76, 0x31, 0x2e, 0x52,
	0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73,
	0x52, 0x65, 0x73, 0x22, 0x00, 0x12, 0x6c, 0x0a, 0x18, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43,
	0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x12, 0x26, 0x2e, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65,
	0x6d, 0x6f, 0x76, 0x65, 0x43, 0x68, 0x61, 0x6e, 0x6e, 0x65, 0x6c, 0x43, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65, 0x71, 0x1a, 0x26, 0x2e, 0x74, 0x68, 0x69, 0x6e,
	0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x52, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x43, 0x68, 0x61, 0x6e,
	0x6e, 0x65, 0x6c, 0x43, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x65,
	0x73, 0x22, 0x00, 0x12, 0x72, 0x0a, 0x1a, 0x55, 0x6e, 0x73, 0x65, 0x74, 0x50, 0x61, 0x72, 0x65,
	0x6e, 0x74, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x46, 0x72, 0x6f, 0x6d, 0x54, 0x68, 0x69, 0x6e, 0x67,
	0x73, 0x12, 0x28, 0x2e, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x6e,
	0x73, 0x65, 0x74, 0x50, 0x61, 0x72, 0x65, 0x6e, 0x74, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x46, 0x72,
	0x6f, 0x6d, 0x54, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x52, 0x65, 0x71, 0x1a, 0x28, 0x2e, 0x74, 0x68,
	0x69, 0x6e, 0x67, 0x73, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x6e, 0x73, 0x65, 0x74, 0x50, 0x61, 0x72,
	0x65, 0x6e, 0x74, 0x47, 0x72, 0x6f, 0x75, 0x70, 0x46, 0x72, 0x6f, 0x6d, 0x54, 0x68, 0x69, 0x6e,
	0x67, 0x73, 0x52, 0x65, 0x73, 0x22, 0x00, 0x42, 0x37, 0x5a, 0x35, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x61, 0x62, 0x73, 0x6d, 0x61, 0x63, 0x68, 0x2f, 0x6d, 0x61,
	0x67, 0x69, 0x73, 0x74, 0x72, 0x61, 0x6c, 0x61, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61,
	0x6c, 0x2f, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x74, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x2f, 0x76, 0x31,
	0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_things_v1_things_proto_rawDescOnce sync.Once
	file_things_v1_things_proto_rawDescData = file_things_v1_things_proto_rawDesc
)

func file_things_v1_things_proto_rawDescGZIP() []byte {
	file_things_v1_things_proto_rawDescOnce.Do(func() {
		file_things_v1_things_proto_rawDescData = protoimpl.X.CompressGZIP(file_things_v1_things_proto_rawDescData)
	})
	return file_things_v1_things_proto_rawDescData
}

var file_things_v1_things_proto_msgTypes = make([]protoimpl.MessageInfo, 6)
var file_things_v1_things_proto_goTypes = []any{
	(*AuthnReq)(nil),                      // 0: things.v1.AuthnReq
	(*AuthnRes)(nil),                      // 1: things.v1.AuthnRes
	(*RemoveChannelConnectionsReq)(nil),   // 2: things.v1.RemoveChannelConnectionsReq
	(*RemoveChannelConnectionsRes)(nil),   // 3: things.v1.RemoveChannelConnectionsRes
	(*UnsetParentGroupFromThingsReq)(nil), // 4: things.v1.UnsetParentGroupFromThingsReq
	(*UnsetParentGroupFromThingsRes)(nil), // 5: things.v1.UnsetParentGroupFromThingsRes
	(*v1.RetrieveEntityReq)(nil),          // 6: common.v1.RetrieveEntityReq
	(*v1.RetrieveEntitiesReq)(nil),        // 7: common.v1.RetrieveEntitiesReq
	(*v1.AddConnectionsReq)(nil),          // 8: common.v1.AddConnectionsReq
	(*v1.RemoveConnectionsReq)(nil),       // 9: common.v1.RemoveConnectionsReq
	(*v1.RetrieveEntityRes)(nil),          // 10: common.v1.RetrieveEntityRes
	(*v1.RetrieveEntitiesRes)(nil),        // 11: common.v1.RetrieveEntitiesRes
	(*v1.AddConnectionsRes)(nil),          // 12: common.v1.AddConnectionsRes
	(*v1.RemoveConnectionsRes)(nil),       // 13: common.v1.RemoveConnectionsRes
}
var file_things_v1_things_proto_depIdxs = []int32{
	0,  // 0: things.v1.ThingsService.Authenticate:input_type -> things.v1.AuthnReq
	6,  // 1: things.v1.ThingsService.RetrieveEntity:input_type -> common.v1.RetrieveEntityReq
	7,  // 2: things.v1.ThingsService.RetrieveEntities:input_type -> common.v1.RetrieveEntitiesReq
	8,  // 3: things.v1.ThingsService.AddConnections:input_type -> common.v1.AddConnectionsReq
	9,  // 4: things.v1.ThingsService.RemoveConnections:input_type -> common.v1.RemoveConnectionsReq
	2,  // 5: things.v1.ThingsService.RemoveChannelConnections:input_type -> things.v1.RemoveChannelConnectionsReq
	4,  // 6: things.v1.ThingsService.UnsetParentGroupFromThings:input_type -> things.v1.UnsetParentGroupFromThingsReq
	1,  // 7: things.v1.ThingsService.Authenticate:output_type -> things.v1.AuthnRes
	10, // 8: things.v1.ThingsService.RetrieveEntity:output_type -> common.v1.RetrieveEntityRes
	11, // 9: things.v1.ThingsService.RetrieveEntities:output_type -> common.v1.RetrieveEntitiesRes
	12, // 10: things.v1.ThingsService.AddConnections:output_type -> common.v1.AddConnectionsRes
	13, // 11: things.v1.ThingsService.RemoveConnections:output_type -> common.v1.RemoveConnectionsRes
	3,  // 12: things.v1.ThingsService.RemoveChannelConnections:output_type -> things.v1.RemoveChannelConnectionsRes
	5,  // 13: things.v1.ThingsService.UnsetParentGroupFromThings:output_type -> things.v1.UnsetParentGroupFromThingsRes
	7,  // [7:14] is the sub-list for method output_type
	0,  // [0:7] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_things_v1_things_proto_init() }
func file_things_v1_things_proto_init() {
	if File_things_v1_things_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_things_v1_things_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   6,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_things_v1_things_proto_goTypes,
		DependencyIndexes: file_things_v1_things_proto_depIdxs,
		MessageInfos:      file_things_v1_things_proto_msgTypes,
	}.Build()
	File_things_v1_things_proto = out.File
	file_things_v1_things_proto_rawDesc = nil
	file_things_v1_things_proto_goTypes = nil
	file_things_v1_things_proto_depIdxs = nil
}

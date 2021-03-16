// Code generated by protoc-gen-go. DO NOT EDIT.
// source: rpc/service.proto

package cache

import (
	fmt "fmt"
	common "github.com/aquasecurity/trivy/rpc/common"
	proto "github.com/golang/protobuf/proto"
	_ "github.com/golang/protobuf/ptypes/empty"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type ArtifactInfo struct {
	SchemaVersion        int32                `protobuf:"varint,1,opt,name=schema_version,json=schemaVersion,proto3" json:"schema_version,omitempty"`
	Architecture         string               `protobuf:"bytes,2,opt,name=architecture,proto3" json:"architecture,omitempty"`
	Created              *timestamp.Timestamp `protobuf:"bytes,3,opt,name=created,proto3" json:"created,omitempty"`
	DockerVersion        string               `protobuf:"bytes,4,opt,name=docker_version,json=dockerVersion,proto3" json:"docker_version,omitempty"`
	Os                   string               `protobuf:"bytes,5,opt,name=os,proto3" json:"os,omitempty"`
	HistoryPackages      []*common.Package    `protobuf:"bytes,6,rep,name=history_packages,json=historyPackages,proto3" json:"history_packages,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *ArtifactInfo) Reset()         { *m = ArtifactInfo{} }
func (m *ArtifactInfo) String() string { return proto.CompactTextString(m) }
func (*ArtifactInfo) ProtoMessage()    {}
func (*ArtifactInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec64d44e618a02a6, []int{0}
}

func (m *ArtifactInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ArtifactInfo.Unmarshal(m, b)
}
func (m *ArtifactInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ArtifactInfo.Marshal(b, m, deterministic)
}
func (m *ArtifactInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ArtifactInfo.Merge(m, src)
}
func (m *ArtifactInfo) XXX_Size() int {
	return xxx_messageInfo_ArtifactInfo.Size(m)
}
func (m *ArtifactInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_ArtifactInfo.DiscardUnknown(m)
}

var xxx_messageInfo_ArtifactInfo proto.InternalMessageInfo

func (m *ArtifactInfo) GetSchemaVersion() int32 {
	if m != nil {
		return m.SchemaVersion
	}
	return 0
}

func (m *ArtifactInfo) GetArchitecture() string {
	if m != nil {
		return m.Architecture
	}
	return ""
}

func (m *ArtifactInfo) GetCreated() *timestamp.Timestamp {
	if m != nil {
		return m.Created
	}
	return nil
}

func (m *ArtifactInfo) GetDockerVersion() string {
	if m != nil {
		return m.DockerVersion
	}
	return ""
}

func (m *ArtifactInfo) GetOs() string {
	if m != nil {
		return m.Os
	}
	return ""
}

func (m *ArtifactInfo) GetHistoryPackages() []*common.Package {
	if m != nil {
		return m.HistoryPackages
	}
	return nil
}

type PutArtifactRequest struct {
	ArtifactId           string        `protobuf:"bytes,1,opt,name=artifact_id,json=artifactId,proto3" json:"artifact_id,omitempty"`
	ArtifactInfo         *ArtifactInfo `protobuf:"bytes,2,opt,name=artifact_info,json=artifactInfo,proto3" json:"artifact_info,omitempty"`
	XXX_NoUnkeyedLiteral struct{}      `json:"-"`
	XXX_unrecognized     []byte        `json:"-"`
	XXX_sizecache        int32         `json:"-"`
}

func (m *PutArtifactRequest) Reset()         { *m = PutArtifactRequest{} }
func (m *PutArtifactRequest) String() string { return proto.CompactTextString(m) }
func (*PutArtifactRequest) ProtoMessage()    {}
func (*PutArtifactRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec64d44e618a02a6, []int{1}
}

func (m *PutArtifactRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PutArtifactRequest.Unmarshal(m, b)
}
func (m *PutArtifactRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PutArtifactRequest.Marshal(b, m, deterministic)
}
func (m *PutArtifactRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PutArtifactRequest.Merge(m, src)
}
func (m *PutArtifactRequest) XXX_Size() int {
	return xxx_messageInfo_PutArtifactRequest.Size(m)
}
func (m *PutArtifactRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PutArtifactRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PutArtifactRequest proto.InternalMessageInfo

func (m *PutArtifactRequest) GetArtifactId() string {
	if m != nil {
		return m.ArtifactId
	}
	return ""
}

func (m *PutArtifactRequest) GetArtifactInfo() *ArtifactInfo {
	if m != nil {
		return m.ArtifactInfo
	}
	return nil
}

type BlobInfo struct {
	SchemaVersion int32                 `protobuf:"varint,1,opt,name=schema_version,json=schemaVersion,proto3" json:"schema_version,omitempty"`
	Os            *common.OS            `protobuf:"bytes,2,opt,name=os,proto3" json:"os,omitempty"`
	PackageInfos  []*common.PackageInfo `protobuf:"bytes,3,rep,name=package_infos,json=packageInfos,proto3" json:"package_infos,omitempty"`
	Applications  []*common.Application `protobuf:"bytes,4,rep,name=applications,proto3" json:"applications,omitempty"`
	OpaqueDirs    []string              `protobuf:"bytes,5,rep,name=opaque_dirs,json=opaqueDirs,proto3" json:"opaque_dirs,omitempty"`
	WhiteoutFiles []string              `protobuf:"bytes,6,rep,name=whiteout_files,json=whiteoutFiles,proto3" json:"whiteout_files,omitempty"`
	Digest        string                `protobuf:"bytes,7,opt,name=digest,proto3" json:"digest,omitempty"`
	DiffId        string                `protobuf:"bytes,8,opt,name=diff_id,json=diffId,proto3" json:"diff_id,omitempty"`
	// TODO: fix me
	IacResults           []*IaCResult `protobuf:"bytes,9,rep,name=iac_results,json=iacResults,proto3" json:"iac_results,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *BlobInfo) Reset()         { *m = BlobInfo{} }
func (m *BlobInfo) String() string { return proto.CompactTextString(m) }
func (*BlobInfo) ProtoMessage()    {}
func (*BlobInfo) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec64d44e618a02a6, []int{2}
}

func (m *BlobInfo) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BlobInfo.Unmarshal(m, b)
}
func (m *BlobInfo) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BlobInfo.Marshal(b, m, deterministic)
}
func (m *BlobInfo) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BlobInfo.Merge(m, src)
}
func (m *BlobInfo) XXX_Size() int {
	return xxx_messageInfo_BlobInfo.Size(m)
}
func (m *BlobInfo) XXX_DiscardUnknown() {
	xxx_messageInfo_BlobInfo.DiscardUnknown(m)
}

var xxx_messageInfo_BlobInfo proto.InternalMessageInfo

func (m *BlobInfo) GetSchemaVersion() int32 {
	if m != nil {
		return m.SchemaVersion
	}
	return 0
}

func (m *BlobInfo) GetOs() *common.OS {
	if m != nil {
		return m.Os
	}
	return nil
}

func (m *BlobInfo) GetPackageInfos() []*common.PackageInfo {
	if m != nil {
		return m.PackageInfos
	}
	return nil
}

func (m *BlobInfo) GetApplications() []*common.Application {
	if m != nil {
		return m.Applications
	}
	return nil
}

func (m *BlobInfo) GetOpaqueDirs() []string {
	if m != nil {
		return m.OpaqueDirs
	}
	return nil
}

func (m *BlobInfo) GetWhiteoutFiles() []string {
	if m != nil {
		return m.WhiteoutFiles
	}
	return nil
}

func (m *BlobInfo) GetDigest() string {
	if m != nil {
		return m.Digest
	}
	return ""
}

func (m *BlobInfo) GetDiffId() string {
	if m != nil {
		return m.DiffId
	}
	return ""
}

func (m *BlobInfo) GetIacResults() []*IaCResult {
	if m != nil {
		return m.IacResults
	}
	return nil
}

type PutBlobRequest struct {
	DiffId   string    `protobuf:"bytes,1,opt,name=diff_id,json=diffId,proto3" json:"diff_id,omitempty"`
	BlobInfo *BlobInfo `protobuf:"bytes,2,opt,name=blob_info,json=blobInfo,proto3" json:"blob_info,omitempty"`
	// TODO: fix me
	PolicySignature      string   `protobuf:"bytes,3,opt,name=policy_signature,json=policySignature,proto3" json:"policy_signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PutBlobRequest) Reset()         { *m = PutBlobRequest{} }
func (m *PutBlobRequest) String() string { return proto.CompactTextString(m) }
func (*PutBlobRequest) ProtoMessage()    {}
func (*PutBlobRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec64d44e618a02a6, []int{3}
}

func (m *PutBlobRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PutBlobRequest.Unmarshal(m, b)
}
func (m *PutBlobRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PutBlobRequest.Marshal(b, m, deterministic)
}
func (m *PutBlobRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PutBlobRequest.Merge(m, src)
}
func (m *PutBlobRequest) XXX_Size() int {
	return xxx_messageInfo_PutBlobRequest.Size(m)
}
func (m *PutBlobRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_PutBlobRequest.DiscardUnknown(m)
}

var xxx_messageInfo_PutBlobRequest proto.InternalMessageInfo

func (m *PutBlobRequest) GetDiffId() string {
	if m != nil {
		return m.DiffId
	}
	return ""
}

func (m *PutBlobRequest) GetBlobInfo() *BlobInfo {
	if m != nil {
		return m.BlobInfo
	}
	return nil
}

func (m *PutBlobRequest) GetPolicySignature() string {
	if m != nil {
		return m.PolicySignature
	}
	return ""
}

type PutResponse struct {
	Os                   *common.OS `protobuf:"bytes,1,opt,name=os,proto3" json:"os,omitempty"`
	Eosl                 bool       `protobuf:"varint,2,opt,name=eosl,proto3" json:"eosl,omitempty"`
	XXX_NoUnkeyedLiteral struct{}   `json:"-"`
	XXX_unrecognized     []byte     `json:"-"`
	XXX_sizecache        int32      `json:"-"`
}

func (m *PutResponse) Reset()         { *m = PutResponse{} }
func (m *PutResponse) String() string { return proto.CompactTextString(m) }
func (*PutResponse) ProtoMessage()    {}
func (*PutResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec64d44e618a02a6, []int{4}
}

func (m *PutResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PutResponse.Unmarshal(m, b)
}
func (m *PutResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PutResponse.Marshal(b, m, deterministic)
}
func (m *PutResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PutResponse.Merge(m, src)
}
func (m *PutResponse) XXX_Size() int {
	return xxx_messageInfo_PutResponse.Size(m)
}
func (m *PutResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_PutResponse.DiscardUnknown(m)
}

var xxx_messageInfo_PutResponse proto.InternalMessageInfo

func (m *PutResponse) GetOs() *common.OS {
	if m != nil {
		return m.Os
	}
	return nil
}

func (m *PutResponse) GetEosl() bool {
	if m != nil {
		return m.Eosl
	}
	return false
}

type MissingBlobsRequest struct {
	ArtifactId           string   `protobuf:"bytes,1,opt,name=artifact_id,json=artifactId,proto3" json:"artifact_id,omitempty"`
	BlobIds              []string `protobuf:"bytes,2,rep,name=blob_ids,json=blobIds,proto3" json:"blob_ids,omitempty"`
	PolicySignature      string   `protobuf:"bytes,3,opt,name=policy_signature,json=policySignature,proto3" json:"policy_signature,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MissingBlobsRequest) Reset()         { *m = MissingBlobsRequest{} }
func (m *MissingBlobsRequest) String() string { return proto.CompactTextString(m) }
func (*MissingBlobsRequest) ProtoMessage()    {}
func (*MissingBlobsRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec64d44e618a02a6, []int{5}
}

func (m *MissingBlobsRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MissingBlobsRequest.Unmarshal(m, b)
}
func (m *MissingBlobsRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MissingBlobsRequest.Marshal(b, m, deterministic)
}
func (m *MissingBlobsRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MissingBlobsRequest.Merge(m, src)
}
func (m *MissingBlobsRequest) XXX_Size() int {
	return xxx_messageInfo_MissingBlobsRequest.Size(m)
}
func (m *MissingBlobsRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_MissingBlobsRequest.DiscardUnknown(m)
}

var xxx_messageInfo_MissingBlobsRequest proto.InternalMessageInfo

func (m *MissingBlobsRequest) GetArtifactId() string {
	if m != nil {
		return m.ArtifactId
	}
	return ""
}

func (m *MissingBlobsRequest) GetBlobIds() []string {
	if m != nil {
		return m.BlobIds
	}
	return nil
}

func (m *MissingBlobsRequest) GetPolicySignature() string {
	if m != nil {
		return m.PolicySignature
	}
	return ""
}

type MissingBlobsResponse struct {
	MissingArtifact      bool     `protobuf:"varint,1,opt,name=missing_artifact,json=missingArtifact,proto3" json:"missing_artifact,omitempty"`
	MissingBlobIds       []string `protobuf:"bytes,2,rep,name=missing_blob_ids,json=missingBlobIds,proto3" json:"missing_blob_ids,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *MissingBlobsResponse) Reset()         { *m = MissingBlobsResponse{} }
func (m *MissingBlobsResponse) String() string { return proto.CompactTextString(m) }
func (*MissingBlobsResponse) ProtoMessage()    {}
func (*MissingBlobsResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec64d44e618a02a6, []int{6}
}

func (m *MissingBlobsResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_MissingBlobsResponse.Unmarshal(m, b)
}
func (m *MissingBlobsResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_MissingBlobsResponse.Marshal(b, m, deterministic)
}
func (m *MissingBlobsResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_MissingBlobsResponse.Merge(m, src)
}
func (m *MissingBlobsResponse) XXX_Size() int {
	return xxx_messageInfo_MissingBlobsResponse.Size(m)
}
func (m *MissingBlobsResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_MissingBlobsResponse.DiscardUnknown(m)
}

var xxx_messageInfo_MissingBlobsResponse proto.InternalMessageInfo

func (m *MissingBlobsResponse) GetMissingArtifact() bool {
	if m != nil {
		return m.MissingArtifact
	}
	return false
}

func (m *MissingBlobsResponse) GetMissingBlobIds() []string {
	if m != nil {
		return m.MissingBlobIds
	}
	return nil
}

// TODO: fix me
type IaCResult struct {
	FilePath             string   `protobuf:"bytes,1,opt,name=file_path,json=filePath,proto3" json:"file_path,omitempty"`
	Result               string   `protobuf:"bytes,2,opt,name=result,proto3" json:"result,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *IaCResult) Reset()         { *m = IaCResult{} }
func (m *IaCResult) String() string { return proto.CompactTextString(m) }
func (*IaCResult) ProtoMessage()    {}
func (*IaCResult) Descriptor() ([]byte, []int) {
	return fileDescriptor_ec64d44e618a02a6, []int{7}
}

func (m *IaCResult) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_IaCResult.Unmarshal(m, b)
}
func (m *IaCResult) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_IaCResult.Marshal(b, m, deterministic)
}
func (m *IaCResult) XXX_Merge(src proto.Message) {
	xxx_messageInfo_IaCResult.Merge(m, src)
}
func (m *IaCResult) XXX_Size() int {
	return xxx_messageInfo_IaCResult.Size(m)
}
func (m *IaCResult) XXX_DiscardUnknown() {
	xxx_messageInfo_IaCResult.DiscardUnknown(m)
}

var xxx_messageInfo_IaCResult proto.InternalMessageInfo

func (m *IaCResult) GetFilePath() string {
	if m != nil {
		return m.FilePath
	}
	return ""
}

func (m *IaCResult) GetResult() string {
	if m != nil {
		return m.Result
	}
	return ""
}

func init() {
	proto.RegisterType((*ArtifactInfo)(nil), "wave.cache.v1.ArtifactInfo")
	proto.RegisterType((*PutArtifactRequest)(nil), "wave.cache.v1.PutArtifactRequest")
	proto.RegisterType((*BlobInfo)(nil), "wave.cache.v1.BlobInfo")
	proto.RegisterType((*PutBlobRequest)(nil), "wave.cache.v1.PutBlobRequest")
	proto.RegisterType((*PutResponse)(nil), "wave.cache.v1.PutResponse")
	proto.RegisterType((*MissingBlobsRequest)(nil), "wave.cache.v1.MissingBlobsRequest")
	proto.RegisterType((*MissingBlobsResponse)(nil), "wave.cache.v1.MissingBlobsResponse")
	proto.RegisterType((*IaCResult)(nil), "wave.cache.v1.IaCResult")
}

func init() { proto.RegisterFile("rpc/service.proto", fileDescriptor_ec64d44e618a02a6) }

var fileDescriptor_ec64d44e618a02a6 = []byte{
	// 766 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x54, 0x4d, 0x6f, 0xe3, 0x36,
	0x10, 0x85, 0xec, 0x38, 0xb6, 0xc7, 0x1f, 0x71, 0xd9, 0x36, 0x51, 0x1c, 0x14, 0x71, 0x55, 0x14,
	0x70, 0x2e, 0x32, 0xea, 0x06, 0x05, 0x7a, 0x68, 0xe1, 0x24, 0x6d, 0x51, 0x1f, 0x8a, 0x1a, 0x4a,
	0xd1, 0x02, 0xbd, 0x08, 0x34, 0x45, 0xd9, 0x44, 0x24, 0x51, 0x11, 0x29, 0x07, 0x06, 0xf6, 0xbc,
	0x58, 0xec, 0x6f, 0xdd, 0x1f, 0xb1, 0x20, 0x29, 0xc5, 0x1f, 0xc9, 0x06, 0x9b, 0x9b, 0xe6, 0x71,
	0x34, 0xf3, 0xe6, 0xbd, 0x21, 0xe1, 0x8b, 0x2c, 0x25, 0x23, 0x41, 0xb3, 0x15, 0x23, 0xd4, 0x4d,
	0x33, 0x2e, 0x39, 0xea, 0x3c, 0xe0, 0x15, 0x75, 0x09, 0x26, 0x4b, 0xea, 0xae, 0x7e, 0xe8, 0xff,
	0xb4, 0x60, 0x72, 0x99, 0xcf, 0x5d, 0xc2, 0xe3, 0x11, 0xbe, 0xcf, 0xb1, 0xa0, 0x24, 0xcf, 0x98,
	0x5c, 0x8f, 0x64, 0xc6, 0x56, 0xeb, 0x91, 0xfa, 0x9f, 0xf0, 0x38, 0xe6, 0xc9, 0x6e, 0x99, 0xfe,
	0xf9, 0x82, 0xf3, 0x45, 0x44, 0x47, 0x3a, 0x9a, 0xe7, 0xe1, 0x48, 0xb2, 0x98, 0x0a, 0x89, 0xe3,
	0xb4, 0x48, 0x38, 0xdb, 0x4f, 0xa0, 0x71, 0x2a, 0xd7, 0xe6, 0xd0, 0x79, 0x57, 0x81, 0xf6, 0x55,
	0x26, 0x59, 0x88, 0x89, 0x9c, 0x26, 0x21, 0x47, 0xdf, 0x43, 0x57, 0x90, 0x25, 0x8d, 0xb1, 0xbf,
	0xa2, 0x99, 0x60, 0x3c, 0xb1, 0xad, 0x81, 0x35, 0xac, 0x79, 0x1d, 0x83, 0xfe, 0x6b, 0x40, 0xe4,
	0x40, 0x1b, 0x67, 0x64, 0xc9, 0x24, 0x25, 0x32, 0xcf, 0xa8, 0x5d, 0x19, 0x58, 0xc3, 0xa6, 0xb7,
	0x83, 0xa1, 0x4b, 0xa8, 0x93, 0x8c, 0x62, 0x49, 0x03, 0xbb, 0x3a, 0xb0, 0x86, 0xad, 0x71, 0xdf,
	0x35, 0x54, 0xdc, 0x92, 0x8a, 0xfb, 0x4f, 0xc9, 0xd5, 0x2b, 0x53, 0x15, 0x81, 0x80, 0x93, 0x3b,
	0x9a, 0x3d, 0x12, 0x38, 0xd0, 0xb5, 0x3b, 0x06, 0x2d, 0x09, 0x74, 0xa1, 0xc2, 0x85, 0x5d, 0xd3,
	0x47, 0x15, 0x2e, 0xd0, 0x04, 0x7a, 0x4b, 0x26, 0x24, 0xcf, 0xd6, 0x7e, 0x8a, 0xc9, 0x1d, 0x5e,
	0x50, 0x61, 0x1f, 0x0e, 0xaa, 0xc3, 0xd6, 0xf8, 0x6b, 0x57, 0x2b, 0xe8, 0x1a, 0xf5, 0xdc, 0x99,
	0x39, 0xf5, 0x8e, 0x8a, 0xf4, 0x22, 0x16, 0xce, 0x03, 0xa0, 0x59, 0x2e, 0x4b, 0x31, 0x3c, 0x7a,
	0x9f, 0x53, 0x21, 0xd1, 0x39, 0xb4, 0x70, 0x01, 0xf9, 0x2c, 0xd0, 0x62, 0x34, 0x3d, 0x28, 0xa1,
	0x69, 0x80, 0x26, 0xd0, 0xd9, 0x24, 0x24, 0x21, 0xd7, 0x52, 0xb4, 0xc6, 0x67, 0xee, 0x8e, 0xbd,
	0xee, 0xb6, 0xc8, 0x4a, 0xa7, 0x4d, 0xe4, 0xbc, 0xad, 0x42, 0xe3, 0x3a, 0xe2, 0xf3, 0xd7, 0xe8,
	0x3f, 0xd0, 0xe3, 0x9b, 0x56, 0xbd, 0xdd, 0x01, 0xff, 0xbe, 0xd5, 0x82, 0xfc, 0x0a, 0x9d, 0x42,
	0x08, 0x4d, 0x4b, 0xd8, 0x55, 0xad, 0xc6, 0xe9, 0xb3, 0x6a, 0x18, 0x56, 0xe9, 0x26, 0x10, 0xe8,
	0x17, 0x68, 0xe3, 0x34, 0x8d, 0x18, 0xc1, 0x92, 0xf1, 0x44, 0xd8, 0x07, 0xcf, 0xfd, 0x7e, 0xb5,
	0xc9, 0xf0, 0x76, 0xd2, 0x95, 0x6e, 0x3c, 0xc5, 0xf7, 0x39, 0xf5, 0x03, 0x96, 0x29, 0xa3, 0xaa,
	0x4a, 0x37, 0x03, 0xfd, 0xc6, 0x32, 0xa1, 0x06, 0x7d, 0x50, 0xbb, 0xc2, 0x73, 0xe9, 0x87, 0x2c,
	0x2a, 0xec, 0x6a, 0x7a, 0x9d, 0x12, 0xfd, 0x43, 0x81, 0xe8, 0x18, 0x0e, 0x03, 0xb6, 0xa0, 0x42,
	0xda, 0x75, 0x2d, 0x7d, 0x11, 0xa1, 0x13, 0xa8, 0x07, 0x2c, 0x0c, 0x95, 0x27, 0x8d, 0xf2, 0x20,
	0x0c, 0xa7, 0x01, 0xfa, 0x19, 0x5a, 0x0c, 0x13, 0x3f, 0xa3, 0x22, 0x8f, 0xa4, 0xb0, 0x9b, 0x9a,
	0xb6, 0xbd, 0xe7, 0xc6, 0x14, 0xdf, 0x78, 0x3a, 0xc1, 0x03, 0x86, 0x89, 0xf9, 0x14, 0xce, 0x7b,
	0x0b, 0xba, 0xb3, 0x5c, 0x2a, 0x2f, 0x4a, 0xfb, 0xb7, 0xda, 0x58, 0x3b, 0x6d, 0x2e, 0xa1, 0x39,
	0x8f, 0xf8, 0x7c, 0xdb, 0xf2, 0x93, 0xbd, 0x26, 0xa5, 0xa7, 0x5e, 0x63, 0x5e, 0xba, 0x7b, 0x01,
	0xbd, 0x94, 0x47, 0x8c, 0xac, 0x7d, 0xc1, 0x16, 0x09, 0xd6, 0x57, 0xa7, 0xaa, 0xeb, 0x1e, 0x19,
	0xfc, 0xb6, 0x84, 0x9d, 0x1b, 0x68, 0xcd, 0x72, 0xe9, 0x51, 0x91, 0xf2, 0x44, 0xd0, 0xc2, 0x70,
	0xeb, 0x05, 0xc3, 0x11, 0x1c, 0x50, 0x2e, 0x22, 0x4d, 0xa6, 0xe1, 0xe9, 0x6f, 0xe7, 0x0d, 0x7c,
	0xf9, 0x17, 0x13, 0x82, 0x25, 0x0b, 0x45, 0x46, 0x7c, 0xf6, 0x52, 0x9f, 0x42, 0xc3, 0x4c, 0x17,
	0xa8, 0x25, 0x53, 0xb6, 0xd4, 0xf5, 0x0c, 0x81, 0x78, 0xcd, 0x08, 0x77, 0xf0, 0xd5, 0x6e, 0xf7,
	0x62, 0x96, 0x0b, 0xe8, 0xc5, 0x06, 0xf7, 0xcb, 0x9e, 0x9a, 0x43, 0xc3, 0x3b, 0x2a, 0xf0, 0xf2,
	0xb6, 0xa0, 0xe1, 0x26, 0x75, 0x8f, 0x50, 0x37, 0xde, 0x94, 0x9e, 0x06, 0xc2, 0x99, 0x40, 0xf3,
	0xd1, 0x55, 0x74, 0x06, 0x4d, 0xb5, 0x53, 0x7e, 0x8a, 0xe5, 0xb2, 0x18, 0xaf, 0xa1, 0x80, 0x19,
	0x96, 0x4b, 0xb5, 0x52, 0x66, 0x3b, 0x8a, 0x57, 0xab, 0x88, 0xc6, 0x1f, 0x2c, 0xa8, 0xdd, 0x28,
	0xf3, 0xd0, 0x9f, 0x5a, 0xfb, 0x47, 0x12, 0xdf, 0xee, 0x19, 0xfb, 0xf4, 0x99, 0xe8, 0x1f, 0x3f,
	0x79, 0xda, 0x7e, 0x57, 0xaf, 0x2c, 0x9a, 0x40, 0xbd, 0xd8, 0x28, 0xf4, 0xcd, 0xd3, 0x2a, 0x5b,
	0x9b, 0xf6, 0xc9, 0x0a, 0xff, 0x41, 0x7b, 0x5b, 0x44, 0xe4, 0xec, 0x95, 0x79, 0xc6, 0xdf, 0xfe,
	0x77, 0x2f, 0xe6, 0x18, 0x17, 0xae, 0xeb, 0xff, 0xd7, 0x74, 0xc2, 0xfc, 0x50, 0x77, 0xfc, 0xf1,
	0x63, 0x00, 0x00, 0x00, 0xff, 0xff, 0x15, 0x82, 0x20, 0x4d, 0xa4, 0x06, 0x00, 0x00,
}

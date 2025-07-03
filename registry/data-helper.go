package registry

import (
	"cuelabs.dev/go/oci/ociregistry"
	"cuelabs.dev/go/oci/ociregistry/ocimem"
	"github.com/opencontainers/go-digest"
)

// returns true if the given descriptor's "data" field is non-nil, "digest" and "size" are valid, and if "data" matches them
func isDescriptorDataValid(desc ociregistry.Descriptor) bool {
	return desc.Data != nil &&
		desc.Size == int64(len(desc.Data)) &&
		desc.Digest.Validate() == nil &&
		desc.Digest == digest.NewDigestFromBytes(desc.Digest.Algorithm(), desc.Data)
}

// if the given descriptor's "data" field is valid, returns a new [ociregistry.BlobReader], otherwise returns nil
func descriptorDataReader(desc ociregistry.Descriptor) ociregistry.BlobReader {
	if isDescriptorDataValid(desc) {
		return ocimem.NewBytesReader(desc.Data, desc)
	}
	return nil
}

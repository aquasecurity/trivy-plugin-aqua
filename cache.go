package main

import (
	"net/http"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	trivyCache "github.com/aquasecurity/trivy/pkg/cache"
)

type AquaCache struct {
	cache.ArtifactCache
}

func NewAquaCache(remoteAddr trivyCache.RemoteURL, customHeaders http.Header) AquaCache {
	return AquaCache{trivyCache.NewRemoteCache(remoteAddr, customHeaders)}
}

func (c AquaCache) GetArtifact(artifactID string) (artifactInfo types.ArtifactInfo, err error) {
	panic("not supposed to be called")
}

// GetBlob gets blob information such as layer data from local cache
func (c AquaCache) GetBlob(blobID string) (blobInfo types.BlobInfo, err error) {
	panic("not supposed to be called")
}

// Close closes the local database
func (c AquaCache) Close() (err error) {
	panic("not supposed to be called")
}

// Clear deletes the local database
func (c AquaCache) Clear() (err error) {
	panic("not supposed to be called")
}

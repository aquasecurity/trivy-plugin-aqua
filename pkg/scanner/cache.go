package scanner

import (
	"fmt"

	"github.com/aquasecurity/fanal/cache"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
)

type AquaCache struct {
	cache.ArtifactCache
	cache.LocalArtifactCache
}

func (c AquaCache) MissingBlobs(imageID string, layerIDs []string) (bool, []string, error) {
	return false, []string{}, nil
}

func (c AquaCache) GetArtifact(artifactID string) (artifactInfo ftypes.ArtifactInfo, err error) {
	panic("not supposed to be called")
}

func (c AquaCache) GetBlob(blobID string) (blobInfo ftypes.BlobInfo, err error) {
	panic("not supposed to be called")
}

func (c AquaCache) PutArtifact(imageID string, artifactInfo ftypes.ArtifactInfo) error {
	return nil
}

func (c AquaCache) PutBlob(diffID string, blobInfo ftypes.BlobInfo) error {
	return nil
}

func (c AquaCache) Close() (err error) {
	return nil
}

func (c AquaCache) Clear() (err error) {
	panic("not supposed to be called")
}

func initAquaCache() artifact.InitCache {
	return func(c artifact.Option) (cache.Cache, error) {
		cacheClient, err := cache.NewFSCache(utils.CacheDir())
		if err != nil {
			return cacheClient, fmt.Errorf("failed to create cache client with error: %w", err)
		}
		return cacheClient, nil
	}
}

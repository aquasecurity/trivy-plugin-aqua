package scanner

import (
	"fmt"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/pkg/errors"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/cache"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	trivyPkgUtils "github.com/aquasecurity/trivy/pkg/utils"
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
	return func(_ artifact.Option) (cache.Cache, error) {
		cacheClient, err := cache.NewFSCache(utils.CacheDir())
		if err != nil {
			return cacheClient, fmt.Errorf("failed to create cache client with error: %w", err)
		}
		return cacheClient, nil
	}
}

var errSkipScan = errors.New("skip subsequent processes")

func initFSCache(c artifact.Option) (cache.Cache, error) {
	trivyPkgUtils.SetCacheDir(c.CacheDir)
	cache, err := operation.NewCache(c.CacheOption)
	if err != nil {
		return operation.Cache{}, xerrors.Errorf("unable to initialize the cache: %w", err)
	}

	if c.Reset {
		defer cache.Close()
		if err = cache.Reset(); err != nil {
			return operation.Cache{}, xerrors.Errorf("cache reset error: %w", err)
		}
		return operation.Cache{}, errSkipScan
	}
	if c.ClearCache {
		defer cache.Close()
		if err = cache.ClearArtifacts(); err != nil {
			return operation.Cache{}, xerrors.Errorf("cache clear error: %w", err)
		}
		return operation.Cache{}, errSkipScan
	}
	return cache, nil
}

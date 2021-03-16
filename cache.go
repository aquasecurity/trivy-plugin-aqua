package main

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/aquasecurity/trivy/rpc/common"

	"github.com/aquasecurity/trivy/pkg/rpc"

	cache "github.com/aquasecurity/trivy-plugin-aqua/rpc"

	"github.com/aquasecurity/fanal/types"
)

const (
	waveAPI = "https://wave.aquasec.com"
)

type WaveCache struct {
	rpcClient  cache.Cache
	policyDirs []string
}

func NewWaveCache(policyDirs []string) WaveCache {
	return WaveCache{
		rpcClient:  cache.NewCacheProtobufClient(waveAPI, http.DefaultClient),
		policyDirs: policyDirs,
	}
}

func (w WaveCache) calculatePolicySignature() string {
	// TODO(wave): fix me
	// Calculate the signature of policies
	return "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}

func (w WaveCache) scanIaC(configs []types.Config) []types.Config {
	// TODO(teppei): fix me
	// Load policies
	// policies := trivy.Load(w.policyDirs)

	for _, config := range configs {
		// TODO(teppei): fix me
		// Scan IaC files
		// result := trivy.Scan(policies)

		// dummy result
		result := map[string]interface{}{
			"id":       "POLICY-100",
			"severity": "CRITICAL",
			"meg":      "Not run as root",
		}

		// Overwrite the content with the result
		config.Content = result
	}
	return configs
}

func (w WaveCache) MissingBlobs(artifactID string, blobIDs []string) (missingArtifact bool, missingBlobIDs []string, err error) {
	res, err := w.rpcClient.MissingBlobs(context.Background(), &cache.MissingBlobsRequest{
		ArtifactId:      artifactID,
		BlobIds:         blobIDs,
		PolicySignature: w.calculatePolicySignature(),
	})
	if err != nil {
		return false, nil, err
	}

	return res.MissingArtifact, res.MissingBlobIds, nil
}

func (w WaveCache) PutArtifact(artifactID string, artifactInfo types.ArtifactInfo) (err error) {
	panic("implement me")
}

func (w WaveCache) PutBlob(blobID string, blobInfo types.BlobInfo) (err error) {
	// TODO(teppei): should Trivy's functions
	var packageInfos []*common.PackageInfo
	for _, pkgInfo := range blobInfo.PackageInfos {
		packageInfos = append(packageInfos, &common.PackageInfo{
			FilePath: pkgInfo.FilePath,
			Packages: rpc.ConvertToRPCPkgs(pkgInfo.Packages),
		})
	}

	var applications []*common.Application
	for _, app := range blobInfo.Applications {
		var libs []*common.Library
		for _, lib := range app.Libraries {
			libs = append(libs, &common.Library{
				Name:    lib.Library.Name,
				Version: lib.Library.Version,
			})
		}
		applications = append(applications, &common.Application{
			Type:      app.Type,
			FilePath:  app.FilePath,
			Libraries: libs,
		})
	}

	// Scan IaC config files
	results := w.scanIaC(blobInfo.Configs)

	var iacResults []*cache.IaCResult
	for _, r := range results {
		result, err := json.Marshal(r.Content)
		if err != nil {
			return err
		}
		iacResults = append(iacResults, &cache.IaCResult{
			FilePath: r.FilePath,
			Result:   string(result),
		})
	}

	// TODO(wave): fix me
	_, err = w.rpcClient.PutBlob(context.Background(), &cache.PutBlobRequest{
		DiffId: blobID,
		BlobInfo: &cache.BlobInfo{
			SchemaVersion: int32(blobInfo.SchemaVersion),
			Digest:        blobInfo.Digest,
			DiffId:        blobInfo.Digest,
			Os:            rpc.ConvertToRPCOS(blobInfo.OS),
			PackageInfos:  packageInfos,
			Applications:  applications,
			IacResults:    iacResults,
			OpaqueDirs:    blobInfo.OpaqueDirs,
			WhiteoutFiles: blobInfo.WhiteoutFiles,
		},
	})
	return err
}

func (w WaveCache) GetArtifact(artifactID string) (artifactInfo types.ArtifactInfo, err error) {
	panic("implement me")
}

func (w WaveCache) GetBlob(blobID string) (blobInfo types.BlobInfo, err error) {
	panic("implement me")
}

func (w WaveCache) Close() (err error) {
	panic("implement me")
}

func (w WaveCache) Clear() (err error) {
	panic("implement me")
}

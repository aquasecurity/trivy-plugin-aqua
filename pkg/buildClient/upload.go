package buildClient

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

func (bc *TwirpClient) Upload(results []*buildsecurity.Result, tags map[string]string) error {
	client := buildsecurity.NewBuildSecurityProtobufClient(bc.aquaUrl, &http.Client{})
	ctx := context.Background()

	ctx, err := bc.createContext()
	if err != nil {
		return err
	}

	gitUser := metadata.GetGitUser(bc.scanPath)
	_, branch, err := metadata.GetRepositoryDetails(bc.scanPath)
	if err != nil {
		return err
	}
	commitId := metadata.GetCommitID(bc.scanPath)

	buildSystem := metadata.GetBuildSystem()

	createScanReq := &buildsecurity.CreateScanReq{
		RepositoryID: bc.repoId,
		Results:      results,
		User:         gitUser,
		Branch:       branch,
		Commit:       commitId,
		System:       buildSystem,
		Tags: tags,
	}

	_, err = client.CreateScan(ctx, createScanReq)
	if err != nil {
		return fmt.Errorf("failed sending results with error: %w", err)
	}
	return nil
}

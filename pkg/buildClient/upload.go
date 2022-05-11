package buildClient

import (
	"fmt"
	"net/http"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/scanner"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

func (bc *TwirpClient) Upload(results []*buildsecurity.Result, tags map[string]string) error {
	client := buildsecurity.NewBuildSecurityProtobufClient(bc.aquaUrl, &http.Client{})

	ctx, err := bc.createContext()
	if err != nil {
		return err
	}

	gitUser := metadata.GetGitUser(bc.scanPath)
	_, branch, err := metadata.GetRepositoryDetails(bc.scanPath, bc.c.Command.Name)
	if err != nil {
		return err
	}
	commitId := metadata.GetCommitID(bc.scanPath)

	buildSystem := metadata.GetBuildSystem()

	run, buildID := metadata.GetBuildInfo(buildSystem)
	// add tags only if not exist and allow override
	if _, ok := tags["run"]; !ok {
		if run != "" {
			tags["run"] = run
		}
	}
	if _, ok := tags["build_id"]; !ok {
		if buildID != "" {
			tags["build_id"] = buildID
		}
	}

	createScanReq := &buildsecurity.CreateScanReq{
		RepositoryID: bc.repoId,
		Results:      results,
		User:         gitUser,
		Branch:       branch,
		Commit:       commitId,
		System:       buildSystem,
		Tags:         tags,
		TriggeredBy:  scanner.MatchTriggeredBy(bc.c.String("triggered-by")),
	}

	_, err = client.CreateScan(ctx, createScanReq)
	if err != nil {
		return fmt.Errorf("failed sending results with error: %w", err)
	}
	return nil
}

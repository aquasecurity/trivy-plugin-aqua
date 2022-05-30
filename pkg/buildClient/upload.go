package buildClient

import (
	"fmt"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
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

	triggeredBy := bc.c.String("triggered-by")
	createScanReq := &buildsecurity.CreateScanReq{
		RepositoryID: bc.repoId,
		Results:      results,
		User:         gitUser,
		Branch:       branch,
		Commit:       commitId,
		System:       buildSystem,
		Tags:         tags,
		TriggeredBy:  scanner.MatchTriggeredBy(triggeredBy),
		Run:          run,
		BuildID:      buildID,
	}

	_, err = client.CreateScan(ctx, createScanReq)
	if err != nil {
		return fmt.Errorf("failed sending results with error: %w", err)
	}

	// Send pull request comments
	if triggeredBy == "pr" && len(results) > 0 {
		err = prComments(buildSystem, results)
		if err != nil {
			log.Logger.Info("failed send PR comment logging and continue the scan err: ", err)
		}
	}

	return nil
}

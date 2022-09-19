package buildClient

import (
	"fmt"
	"net/http"

	"github.com/argonsecurity/go-utils/environments/models"
	"github.com/spf13/viper"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/scanner"
)

func (bc *TwirpClient) Upload(results []*buildsecurity.Result,
	tags map[string]string,
	avdUrlMap ResultIdToUrlMap,
	pipelines []*buildsecurity.Pipeline,
	dependencies map[string]*buildsecurity.PackageDependencies,
	envconfig *models.Configuration) error {
	client := buildsecurity.NewBuildSecurityProtobufClient(bc.aquaUrl, &http.Client{})

	ctx, err := bc.createContext()
	if err != nil {
		return err
	}

	triggeredBy := viper.GetString("triggered-by")
	createScanReq := &buildsecurity.CreateScanReq{
		RepositoryID:                 bc.repoId,
		Results:                      results,
		User:                         envconfig.Pusher.Username,
		Branch:                       envconfig.Branch,
		Commit:                       envconfig.CommitSha,
		System:                       string(envconfig.Repository.Source),
		Tags:                         tags,
		TriggeredBy:                  scanner.MatchTriggeredBy(triggeredBy),
		Run:                          envconfig.Run.BuildNumber,
		BuildID:                      envconfig.Run.BuildId,
		Pipelines:                    pipelines,
		TargetPackageDependenciesMap: dependencies,
	}

	_, err = client.CreateScan(ctx, createScanReq)
	if err != nil {
		return fmt.Errorf("failed sending results with error: %w", err)
	}

	// Send pull request comments
	if triggeredBy == "PR" && len(results) > 0 {
		err = prComments(string(envconfig.Repository.Source), results, avdUrlMap, envconfig)
		if err != nil {
			log.Logger.Info("failed send PR comment logging and continue the scan err: ", err)
		}
	}

	return nil
}

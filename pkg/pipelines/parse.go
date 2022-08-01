package pipelines

import (
	"io/ioutil"
	"path/filepath"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	ppConsts "github.com/argonsecurity/pipeline-parser/pkg/consts"
	pp "github.com/argonsecurity/pipeline-parser/pkg/handler"
	ppModels "github.com/argonsecurity/pipeline-parser/pkg/models"
)

func parsePipelineFile(path string, platform ppConsts.Platform) (*ppModels.Pipeline, error) {
	fileData, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result, err := pp.Handle(fileData, platform)
	if err != nil {
		return nil, err
	}
	return result, err

}

func parsePipeline(path string, platform ppConsts.Platform) (*buildsecurity.Pipeline, error) {
	parsedPipeline, err := parsePipelineFile(path, platform)
	if err != nil {
		return nil, err
	}

	pipelineName := filepath.Base(path)
	if parsedPipeline.Name != nil {
		pipelineName = *parsedPipeline.Name
	}

	return &buildsecurity.Pipeline{
		Name:     pipelineName,
		Path:     path,
		Platform: string(platform),
	}, nil
}

func parseGitHubWorkflow(workflowPath string) (*buildsecurity.Pipeline, error) {
	return parsePipeline(workflowPath, ppConsts.GitHubPlatform)
}

func parseGitLabPipelineFile(pipelinePath string) (*buildsecurity.Pipeline, error) {
	return parsePipeline(pipelinePath, ppConsts.GitLabPlatform)
}

func parseAzurePipelineFile(pipelinePath string) (*buildsecurity.Pipeline, error) {
	return parsePipeline(pipelinePath, ppConsts.AzurePlatform)
}

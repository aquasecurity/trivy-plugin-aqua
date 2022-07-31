package pipelines

import (
	"io/ioutil"

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

func parseGitHubWorkflow(workflowPath string) (*Pipeline, error) {
	parsedPipeline, err := parsePipelineFile(workflowPath, ppConsts.GitHubPlatform)
	if err != nil {
		return nil, err
	}

	return &Pipeline{
		ID:       *parsedPipeline.Name,
		Name:     *parsedPipeline.Name,
		Path:     workflowPath,
		Platform: string(ppConsts.GitHubPlatform),
		// Link:     "",
	}, nil
}

func parseGitLabPipelineFile(pipelinePath string) (*Pipeline, error) {
	parsedPipeline, err := parsePipelineFile(pipelinePath, ppConsts.GitLabPlatform)
	if err != nil {
		return nil, err
	}

	return &Pipeline{
		ID:       *parsedPipeline.Name,
		Name:     *parsedPipeline.Name,
		Path:     pipelinePath,
		Platform: string(ppConsts.GitLabPlatform),
		// Link:     "",
	}, nil
}

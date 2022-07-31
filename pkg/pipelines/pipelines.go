package pipelines

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/samber/lo"
)

func getParsedGitHubPipelines(rootDir string) []*Pipeline {
	gitHubWorkflows := getGitHubPipelines(rootDir)
	parsedGithubPipelines := lo.FilterMap(gitHubWorkflows, func(path string, _ int) (*Pipeline, bool) {
		pipeline, err := parseGitHubWorkflow(path)
		return pipeline, err == nil
	})
	return parsedGithubPipelines
}

func getParsedGitLabPipelines(rootDir string) []*Pipeline {
	gitLabPipelines := getGitLabPipelines(rootDir)
	parsedGitLabPipelines := lo.FilterMap(gitLabPipelines, func(path string, _ int) (*Pipeline, bool) {
		pipeline, err := parseGitLabPipelineFile(path)
		return pipeline, err == nil
	})
	return parsedGitLabPipelines
}

func getParsedAzurePipelines(rootDir string) []*Pipeline {
	azurePipelines := getAzurePipelines(rootDir)
	parsedAzurePipelines := lo.FilterMap(azurePipelines, func(path string, _ int) (*Pipeline, bool) {
		pipeline, err := parseAzurePipelineFile(path)
		return pipeline, err == nil
	})
	return parsedAzurePipelines
}

func enhancePipeline(pipeline *Pipeline, rootDir string) error {
	firstCommit, err := git.GetFirstCommit(pipeline.Path)
	if err != nil {
		return err
	}
	pipeline.CreatedBy = firstCommit.Author
	pipeline.CreatedDate = firstCommit.Date

	lastCommit, err := git.GetLastCommit(pipeline.Path)
	if err != nil {
		return err
	}
	pipeline.UpdatedBy = lastCommit.Author
	pipeline.UpdatedDate = lastCommit.Date
	pipeline.CommitSHA = lastCommit.SHA

	pipeline.Path = strings.TrimPrefix(pipeline.Path, rootDir+"/")
	pipeline.ID, err = getPipelineId(rootDir, pipeline.Path)
	if err != nil {
		return err
	}

	return nil
}

func getPipelineId(rootDir, path string) (string, error) {
	scmId, err := metadata.GetScmID(rootDir)
	if err != nil {
		return "", err
	}
	hash := sha1.Sum([]byte(scmId + path))
	return hex.EncodeToString(hash[:]), nil

}

func enhancePipelines(rootDir string, pipelines []*Pipeline) error {
	for _, pipeline := range pipelines {
		if err := enhancePipeline(pipeline, rootDir); err != nil {
			return err
		}
	}
	return nil
}

func GetPipelines(rootDir string) ([]*Pipeline, error) {
	pipelines := []*Pipeline{}
	pipelines = append(pipelines, getParsedGitHubPipelines(rootDir)...)
	pipelines = append(pipelines, getParsedGitLabPipelines(rootDir)...)
	pipelines = append(pipelines, getParsedAzurePipelines(rootDir)...)

	if err := enhancePipelines(rootDir, pipelines); err != nil {
		return nil, err
	}

	return pipelines, nil
}
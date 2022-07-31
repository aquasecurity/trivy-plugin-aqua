package pipelines

import (
	"crypto/md5"
	"encoding/hex"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/samber/lo"
)

func getParsedGitHubPipelines(rootDir string) ([]*buildsecurity.Pipeline, error) {
	gitHubWorkflows, err := getGitHubPipelines(rootDir)
	if err != nil {
		return nil, err
	}

	parsedGithubPipelines := lo.FilterMap(gitHubWorkflows, func(path string, _ int) (*buildsecurity.Pipeline, bool) {
		pipeline, err := parseGitHubWorkflow(path)
		return pipeline, err == nil
	})

	return parsedGithubPipelines, nil
}

func getParsedGitLabPipelines(rootDir string) []*buildsecurity.Pipeline {
	gitLabPipelines := getGitLabPipelines(rootDir)
	parsedGitLabPipelines := lo.FilterMap(gitLabPipelines, func(path string, _ int) (*buildsecurity.Pipeline, bool) {
		pipeline, err := parseGitLabPipelineFile(path)
		return pipeline, err == nil
	})
	return parsedGitLabPipelines
}

func getParsedAzurePipelines(rootDir string) ([]*buildsecurity.Pipeline, error) {
	azurePipelines, err := getAzurePipelines(rootDir)
	if err != nil {
		return nil, err
	}

	parsedAzurePipelines := lo.FilterMap(azurePipelines, func(path string, _ int) (*buildsecurity.Pipeline, bool) {
		pipeline, err := parseAzurePipelineFile(path)
		return pipeline, err == nil
	})
	return parsedAzurePipelines, nil
}

func enhancePipeline(pipeline *buildsecurity.Pipeline, rootDir string) error {
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
	pipeline.LastCommitDate = lastCommit.Date
	pipeline.LastCommitSha = lastCommit.SHA

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
	hash := md5.Sum([]byte(scmId + path))
	return hex.EncodeToString(hash[:]), nil
}

func enhancePipelines(rootDir string, pipelines []*buildsecurity.Pipeline) error {
	var err error
	lo.ForEach(pipelines, func(pipeline *buildsecurity.Pipeline, _ int) {
		if err == nil {
			err = enhancePipeline(pipeline, rootDir)
		}
	})
	return err
}

func GetPipelines(rootDir string) ([]*buildsecurity.Pipeline, error) {
	pipelines := []*buildsecurity.Pipeline{}
	githubPipelines, err := getParsedGitHubPipelines(rootDir)
	if err != nil {
		return nil, err
	}
	pipelines = append(pipelines, githubPipelines...)

	azurePipelines, err := getParsedAzurePipelines(rootDir)
	if err != nil {
		return nil, err
	}
	pipelines = append(pipelines, azurePipelines...)

	pipelines = append(pipelines, getParsedGitLabPipelines(rootDir)...)

	if err := enhancePipelines(rootDir, pipelines); err != nil {
		return nil, err
	}

	return pipelines, nil
}

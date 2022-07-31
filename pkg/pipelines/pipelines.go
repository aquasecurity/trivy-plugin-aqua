package pipelines

import (
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
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

	return nil
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
	if err := enhancePipelines(rootDir, pipelines); err != nil {
		return nil, err
	}

	return pipelines, nil
}

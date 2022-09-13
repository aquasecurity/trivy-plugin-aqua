package pipelines

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/pkg/errors"

	ppConsts "github.com/argonsecurity/pipeline-parser/pkg/consts"
	"github.com/samber/lo"
)

func getParsedGitHubPipelines(rootDir string) ([]*buildsecurity.Pipeline, []string, error) {
	gitHubWorkflows, err := getGitHubPipelines(rootDir)
	if err != nil {
		return nil, nil, err
	}

	parsedGithubPipelines := lo.FilterMap(gitHubWorkflows, func(path string, _ int) (*buildsecurity.Pipeline, bool) {
		pipeline, err := parseGitHubWorkflow(rootDir, path)
		if err != nil {
			log.Logger.Warnf("Failed to parse GitHub workflow: %s", err)
		}
		return pipeline, err == nil
	})

	return parsedGithubPipelines, gitHubWorkflows, nil
}

func getParsedGitLabPipelines(rootDir string) ([]*buildsecurity.Pipeline, []string, error) {
	gitLabPipelines, err := getGitLabPipelines(rootDir)
	if err != nil {
		return nil, nil, err
	}
	parsedGitLabPipelines := lo.FilterMap(gitLabPipelines, func(path string, _ int) (*buildsecurity.Pipeline, bool) {
		pipeline, err := parseGitLabPipelineFile(rootDir, path)
		if err != nil {
			log.Logger.Warnf("Failed to parse GitLab pipeline: %s", err)
		}
		return pipeline, err == nil
	})
	return parsedGitLabPipelines, gitLabPipelines, nil
}

func getParsedAzurePipelines(rootDir string) ([]*buildsecurity.Pipeline, []string, error) {
	azurePipelines, err := getAzurePipelines(rootDir)
	if err != nil {
		return nil, nil, err
	}

	parsedAzurePipelines := lo.FilterMap(azurePipelines, func(path string, _ int) (*buildsecurity.Pipeline, bool) {
		pipeline, err := parseAzurePipelineFile(rootDir, path)
		if err != nil {
			log.Logger.Warnf("Failed to parse Azure pipeline: %s", err)
		}
		return pipeline, err == nil
	})
	return parsedAzurePipelines, azurePipelines, nil
}

func enhancePipeline(pipeline *buildsecurity.Pipeline, rootDir string) error {
	pipelineFullPath := filepath.Join(rootDir, pipeline.Path)
	firstCommit, err := git.GetFirstCommit(pipelineFullPath)
	if err != nil {
		return err
	}
	pipeline.CreatedBy = firstCommit.Author
	pipeline.CreatedDate = firstCommit.Date

	lastCommit, err := git.GetLastCommit(pipelineFullPath)
	if err != nil {
		return err
	}
	pipeline.UpdatedBy = lastCommit.Author
	pipeline.LastCommitDate = lastCommit.Date
	pipeline.LastCommitSha = lastCommit.SHA

	return nil
}

func enhancePipelines(rootDir string, pipelines []*buildsecurity.Pipeline) {
	lo.ForEach(pipelines, func(pipeline *buildsecurity.Pipeline, _ int) {
		if err := enhancePipeline(pipeline, rootDir); err != nil {
			log.Logger.Errorf("Failed to enhance pipeline: %s", err)
		}
	})
}

func getPipelinesFiles(rootDir string, pipelinePaths []string, platform ppConsts.Platform) ([]types.File, error) {
	var files []types.File
	for _, pipelinePath := range pipelinePaths {
		content, err := os.ReadFile(pipelinePath)
		if err != nil {
			return nil, err
		}

		relPath, err := filepath.Rel(rootDir, pipelinePath)
		if err != nil {
			relPath = pipelinePath
		}

		files = append(files, types.File{
			Path:    relPath,
			Content: content,
			Type:    string(platform),
		})
	}
	return files, nil
}

func getPipelines(rootDir string) ([]*buildsecurity.Pipeline, []types.File, error) {
	var files []types.File
	pipelines := []*buildsecurity.Pipeline{}
	githubPipelines, githubPaths, err := getParsedGitHubPipelines(rootDir)
	if err != nil {
		return nil, nil, err
	}

	pipelines = append(pipelines, githubPipelines...)
	githubFiles, err := getPipelinesFiles(rootDir, githubPaths, ppConsts.GitHubPlatform)
	if err != nil {
		return nil, nil, err
	}
	files = append(files, githubFiles...)

	azurePipelines, azurePaths, err := getParsedAzurePipelines(rootDir)
	if err != nil {
		return nil, nil, err
	}

	pipelines = append(pipelines, azurePipelines...)
	azureFiles, err := getPipelinesFiles(rootDir, azurePaths, ppConsts.AzurePlatform)
	if err != nil {
		return nil, nil, err
	}
	files = append(files, azureFiles...)

	gitlabPipelines, gitlabPaths, err := getParsedGitLabPipelines(rootDir)
	if err != nil {
		return nil, nil, err
	}

	pipelines = append(pipelines, gitlabPipelines...)
	gitlabFiles, err := getPipelinesFiles(rootDir, gitlabPaths, ppConsts.GitLabPlatform)
	if err != nil {
		return nil, nil, err
	}
	files = append(files, gitlabFiles...)
	enhancePipelines(rootDir, pipelines)

	return pipelines, files, nil
}

func scanPipelines(ctx context.Context, repositoryPipelines []*buildsecurity.Pipeline, files []types.File) (trivyTypes.Results, error) {
	memFs, sourcesMap, err := CreateMemoryFs(files)
	if err != nil {
		return nil, errors.Wrap(err, "failed create memory fs")
	}

	pipelineScanner := NewScanner()
	policyReaders, err := getPolicyReaders()
	if err != nil {
		return nil, errors.Wrap(err, "failed get policy readers")
	}
	pipelineScanner.SetPolicyReaders(policyReaders)

	scanResults, err := pipelineScanner.ScanFS(context.WithValue(ctx, "sourcesMap", sourcesMap), memFs, ".")
	if err != nil {
		return nil, errors.Wrap(err, "failed scan pipelines")
	}
	results := misconfsToResults(resultsToMisconf("pipeline", pipelineScanner.Name(), scanResults))
	return results, nil
}

func ExecutePipelineScanning(rootDir string) ([]*buildsecurity.Pipeline, trivyTypes.Results, error) {
	defer func() {
		if err := recover(); err != nil {
			log.Logger.Errorw("panic occurred", "error", err)
		}
	}()

	pipelines, files, err := getPipelines(rootDir)
	if err != nil {
		return nil, nil, err
	}

	results, err := scanPipelines(context.Background(), pipelines, files)
	if err != nil {
		return nil, nil, err
	}

	return pipelines, results, nil
}

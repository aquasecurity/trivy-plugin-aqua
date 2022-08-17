package pipelines

import (
	// #nosec
	"crypto/md5"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	ppConsts "github.com/argonsecurity/pipeline-parser/pkg/consts"
	pp "github.com/argonsecurity/pipeline-parser/pkg/handler"
	ppModels "github.com/argonsecurity/pipeline-parser/pkg/models"
)

func parsePipelineFile(path string, platform ppConsts.Platform) (*ppModels.Pipeline, error) {
	fileData, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	result, err := pp.Handle(fileData, platform)
	if err != nil {
		return nil, err
	}
	return result, err

}

func parsePipeline(rootDir, path string, platform ppConsts.Platform) (*buildsecurity.Pipeline, error) {
	parsedPipeline, err := parsePipelineFile(path, platform)
	if err != nil {
		return nil, err
	}

	pipelineName := filepath.Base(path)
	if parsedPipeline.Name != nil && *parsedPipeline.Name != "" {
		pipelineName = *parsedPipeline.Name
	}

	relativePath := getRelativePath(rootDir, path)

	return &buildsecurity.Pipeline{
		ID:       getPipelineId(rootDir, relativePath),
		Name:     pipelineName,
		Path:     relativePath,
		Platform: string(platform),
	}, nil
}

func getRelativePath(rootDir string, pipelinePath string) string {
	return strings.TrimPrefix(pipelinePath, rootDir+"/")
}

func getPipelineId(rootDir, path string) string {
	scmId := metadata.GetScmID(rootDir)

	// #nosec - MD5 is used to generate a unique ID
	hash := md5.Sum([]byte(scmId + path))
	return hex.EncodeToString(hash[:])
}

func parseGitHubWorkflow(rootDir, workflowPath string) (*buildsecurity.Pipeline, error) {
	return parsePipeline(rootDir, workflowPath, ppConsts.GitHubPlatform)
}

func parseGitLabPipelineFile(rootDir, pipelinePath string) (*buildsecurity.Pipeline, error) {
	return parsePipeline(rootDir, pipelinePath, ppConsts.GitLabPlatform)
}

func parseAzurePipelineFile(rootDir, pipelinePath string) (*buildsecurity.Pipeline, error) {
	return parsePipeline(rootDir, pipelinePath, ppConsts.AzurePlatform)
}

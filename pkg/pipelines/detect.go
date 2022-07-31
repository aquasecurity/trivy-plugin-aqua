package pipelines

import (
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	_ "embed"
)

const (
	gitHubWorkflowsDir = ".github/workflows"
	gitLabPipelineFile = ".gitlab-ci.yml"
)

func hasSuffixes(path string, suffixes ...string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

func isYamlFile(path string, info os.FileInfo) bool {
	return !info.IsDir() && hasSuffixes(path, ".yml", ".yaml")
}

func getGitHubPipelines(rootDir string) []string {
	workflowsDir := filepath.Join(rootDir, gitHubWorkflowsDir)
	if _, err := os.Stat(workflowsDir); os.IsNotExist(err) {
		return nil
	}

	var pipelines []string
	filepath.Walk(workflowsDir, func(path string, info fs.FileInfo, err error) error {
		if isYamlFile(path, info) {
			pipelines = append(pipelines, path)
		}
		return nil
	})
	return pipelines
}

func getGitlabPipelines(rootDir string) []string {
	gitLabPipelineFilename := filepath.Join(rootDir, gitLabPipelineFile)
	if _, err := os.Stat(gitLabPipelineFilename); os.IsNotExist(err) {
		return nil
	}
	return []string{gitLabPipelineFilename}
}

func getAzurePipelines(rootDir string) []string {
	var pipelines []string
	filepath.Walk(rootDir, func(path string, info fs.FileInfo, err error) error {
		if !isYamlFile(path, info) {
			return nil
		}
		if buf, err := ioutil.ReadFile(path); err != nil && strings.Contains(string(buf), "pool:") {
			pipelines = append(pipelines, path)
		}

		return nil
	})
	return pipelines
}

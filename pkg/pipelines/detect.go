package pipelines

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/argonsecurity/go-environments/logger"
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
	var pipelines []string
	if err := filepath.Walk(rootDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.Contains(path, gitHubWorkflowsDir) && isYamlFile(path, info) {
			pipelines = append(pipelines, path)
		}
		return nil
	}); err != nil {
		logger.Errorf(err, "Failed to walk the path: %s", err)
		return nil
	}

	return pipelines
}

func getGitLabPipelines(rootDir string) []string {
	var pipelines []string
	if err := filepath.Walk(rootDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if strings.Contains(path, gitLabPipelineFile) && isYamlFile(path, info) {
			pipelines = append(pipelines, path)
		}
		return nil
	}); err != nil {
		logger.Errorf(err, "Failed to walk the path: %s", err)
		return nil
	}

	return pipelines
}

func getAzurePipelines(rootDir string) []string {
	var pipelines []string
	if err := filepath.Walk(rootDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !isYamlFile(path, info) {
			return nil
		}
		if buf, err := os.ReadFile(path); err == nil && strings.Contains(string(buf), "pool:") {
			pipelines = append(pipelines, path)
		}

		return nil
	}); err != nil {
		logger.Errorf(err, "Failed to walk the path: %s", err)
		return nil
	}

	return pipelines
}

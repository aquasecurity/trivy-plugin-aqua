package test

import (
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/pipelines"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy-plugin-aqua/test/mocks"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

var (
	firstCommit = git.Commit{
		SHA:    "00000000000000000000000000",
		Date:   "2020-01-01T00:00:00Z",
		Author: "John Doe",
	}

	lastCommit = git.Commit{
		SHA:    "11111111111111111111111111",
		Date:   "2020-01-01T00:00:00Z",
		Author: "Alice Bob",
	}
)

type pipelineTestResult struct {
	pipelines                    []*buildsecurity.Pipeline
	pipelineMisconfigurationsIds map[string][]string // map of pipeline id to misconfiguration ids
}

func getTestFixturePath(dirName string) string {
	return fmt.Sprintf("fixtures/pipelines/%s", dirName)
}

func TestPipelines(t *testing.T) {

	testCases := []struct {
		name      string
		dir       string
		want      pipelineTestResult
		wantErr   bool
		gitClient *mocks.MockGitClient
	}{
		{
			name: "github",
			dir:  "github",
			want: pipelineTestResult{
				pipelines: []*buildsecurity.Pipeline{
					{
						Name:           "Argon",
						Path:           ".github/workflows/github-workflow.yaml",
						Platform:       "github",
						ID:             "6f25aa81a90ec44064b5b4cd5efeeaeb",
						CreatedDate:    firstCommit.Date,
						LastCommitDate: lastCommit.Date,
						LastCommitSha:  lastCommit.SHA,
						CreatedBy:      firstCommit.Author,
						UpdatedBy:      lastCommit.Author,
					},
					{
						Name:           "Another",
						Path:           ".github/workflows/another-workflow.yaml",
						Platform:       "github",
						ID:             "7dbf677abd33b0e9ac85632e62b9020e",
						CreatedDate:    firstCommit.Date,
						LastCommitDate: lastCommit.Date,
						LastCommitSha:  lastCommit.SHA,
						CreatedBy:      firstCommit.Author,
						UpdatedBy:      lastCommit.Author,
					},
				},
				pipelineMisconfigurationsIds: map[string][]string{
					"6f25aa81a90ec44064b5b4cd5efeeaeb": {
						"DEPENDENCY_PINNED_VERSION",
						"PERSIST_CREDENTIALS",
						"UNTRUSTED_INPUT_USAGE",
						"EVAL_COMMAND",
					},
					"7dbf677abd33b0e9ac85632e62b9020e": {
						"VARIABLES_LOGGING",
						"UNTRUSTED_INPUT_NO_ENV",
						"UNTRUSTED_INPUT_USAGE",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "gitlab",
			dir:  "gitlab",
			want: pipelineTestResult{
				pipelines: []*buildsecurity.Pipeline{
					{
						Name:           ".gitlab-ci.yml",
						Path:           ".gitlab-ci.yml",
						Platform:       "gitlab",
						ID:             "0c8c82fe9e5f3000647429d551cdc171",
						CreatedDate:    firstCommit.Date,
						LastCommitDate: lastCommit.Date,
						LastCommitSha:  lastCommit.SHA,
						CreatedBy:      firstCommit.Author,
						UpdatedBy:      lastCommit.Author,
					},
					{
						Name:           ".gitlab-ci.yml",
						Path:           "another/.gitlab-ci.yml",
						Platform:       "gitlab",
						ID:             "895459c423ac62b66889133506ce722b",
						CreatedDate:    firstCommit.Date,
						LastCommitDate: lastCommit.Date,
						LastCommitSha:  lastCommit.SHA,
						CreatedBy:      firstCommit.Author,
						UpdatedBy:      lastCommit.Author,
					},
				},
				pipelineMisconfigurationsIds: map[string][]string{
					"0c8c82fe9e5f3000647429d551cdc171": {
						"EVAL_COMMAND",
						"INSECURE_FETCHING",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "azure",
			dir:  "azure",
			want: pipelineTestResult{
				pipelines: []*buildsecurity.Pipeline{
					{
						Name:           "azure-pipelines.yaml",
						Path:           "azure-pipelines.yaml",
						Platform:       "azure",
						ID:             "80611fdce4e780cf7b3abe982814b6eb",
						CreatedDate:    firstCommit.Date,
						LastCommitDate: lastCommit.Date,
						LastCommitSha:  lastCommit.SHA,
						CreatedBy:      firstCommit.Author,
						UpdatedBy:      lastCommit.Author,
					},
				},
				pipelineMisconfigurationsIds: map[string][]string{
					"80611fdce4e780cf7b3abe982814b6eb": {
						"EXTRA_INDEX_URL",
						"HTTP_USAGE",
						"INSECURE_FETCHING",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "no-pipelines",
			dir:  "no-pipelines",
			want: pipelineTestResult{
				pipelines: []*buildsecurity.Pipeline{},
			},
			wantErr: false,
		},
		{
			name: "invalid-yaml",
			dir:  "invalid-yaml",
			want: pipelineTestResult{
				pipelines: []*buildsecurity.Pipeline{},
			},
			wantErr: false,
		},
		{
			name:    "non-existent-dir",
			dir:     "non-existent-dir",
			wantErr: true,
		},
		{
			name: "git-error",
			dir:  "azure",
			want: pipelineTestResult{
				pipelines: []*buildsecurity.Pipeline{
					{
						Name:           "azure-pipelines.yaml",
						Path:           "azure-pipelines.yaml",
						Platform:       "azure",
						ID:             "80611fdce4e780cf7b3abe982814b6eb",
						CreatedDate:    "",
						LastCommitDate: "",
						LastCommitSha:  "",
						CreatedBy:      "",
						UpdatedBy:      "",
					},
				},
				pipelineMisconfigurationsIds: map[string][]string{
					"80611fdce4e780cf7b3abe982814b6eb": {
						"EXTRA_INDEX_URL",
						"HTTP_USAGE",
						"INSECURE_FETCHING",
					},
				},
			},
			gitClient: (&mocks.MockGitClient{}).SetError(errors.New("git error")),
			wantErr:   false,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			dirPath := getTestFixturePath(tt.dir)
			mockGitClient := tt.gitClient
			if mockGitClient == nil {
				mockGitClient = (&mocks.MockGitClient{}).SetFirstCommit(firstCommit).SetLastCommit(lastCommit)
			}
			mocks.SetGitMock(mockGitClient)

			pipelines, results, err := pipelines.ExecutePipelineScanning(dirPath)
			if err != nil {
				if tt.wantErr {
					t.Logf("Received expected error %s", err.Error())
					return
				}
				t.Error(err.Error())
			}

			if err == nil && tt.wantErr {
				t.Error("Expected error but got none")
				return
			}

			sortPipelines(pipelines)
			sortPipelines(tt.want.pipelines)
			assert.Equal(t, tt.want.pipelines, pipelines)

			for _, pipeline := range pipelines {
				misconfigurationsIds := getPipelineMisconfigurationsFromResult(pipeline.Path, results)
				expectedMisconfigurations := tt.want.pipelineMisconfigurationsIds[pipeline.ID]
				slices.Sort(expectedMisconfigurations)

				assert.Equal(t, expectedMisconfigurations, misconfigurationsIds)
			}
		})
	}
}

func getPipelineMisconfigurationsFromResult(pipelinePath string, results trivyTypes.Results) []string {
	var misconfigurations []string
	for _, result := range results {
		if result.Target == pipelinePath && result.Type == "pipeline" {
			for _, misconfiguration := range result.Misconfigurations {
				if misconfiguration.Status != "PASS" {
					misconfigurations = append(misconfigurations, misconfiguration.ID)
				}
			}
		}
	}
	slices.Sort(misconfigurations)
	return misconfigurations
}

func sortPipelines(pipelines []*buildsecurity.Pipeline) {
	sort.Slice(pipelines, func(i, j int) bool {
		return pipelines[i].ID < pipelines[j].ID
	})
}

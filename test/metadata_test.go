package test

import (
	"fmt"
	"os"
	"testing"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_get_repo_name_from_env(t *testing.T) {

	possibleRepoEnvVars := []string{
		"GITHUB_REPOSITORY",
		"BITBUCKET_REPO_SLUG",
		"CI_PROJECT_PATH",
		"CODEBUILD_PROJECT",
		"BUILD_REPOSITORY_NAME",
		"FALLBACK_REPOSITORY",
	}

	possibleBranchEnvVars := []string{
		"GITHUB_REF_NAME",
		"GIT_BRANCH",
		"BITBUCKET_BRANCH",
		"CI_COMMIT_REF_NAME",
		"CODEBUILD_GIT_BRANCH",
		"BUILD_SOURCEBRANCHNAME",
	}

	for i := range possibleRepoEnvVars {

		err := os.Setenv(possibleRepoEnvVars[i], fmt.Sprintf("REPOSITORY_%d", i))
		require.NoError(t, err)
		err = os.Setenv(possibleBranchEnvVars[i], fmt.Sprintf("BRANCH_%d", i))
		require.NoError(t, err)

		repoName, branch, err := metadata.GetRepositoryDetails("", "")
		require.NoError(t, err)

		assert.Equal(t, fmt.Sprintf("REPOSITORY_%d", i), repoName)
		assert.Equal(t, fmt.Sprintf("BRANCH_%d", i), branch)
		err = os.Unsetenv(possibleRepoEnvVars[i])
		require.NoError(t, err)
		err = os.Unsetenv(possibleBranchEnvVars[i])
		require.NoError(t, err)
	}
}

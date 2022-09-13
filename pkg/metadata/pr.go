package metadata

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/pkg/errors"
)

func GetBaseRef() (r string) {
	buildSystem := GetBuildSystem()
	switch buildSystem {
	case Azure:
		return fmt.Sprintf(
			"origin/%s",
			strings.ReplaceAll(os.Getenv("SYSTEM_PULLREQUEST_TARGETBRANCH"), "refs/heads/", ""))
	case Bitbucket:
		return os.Getenv("BITBUCKET_PR_DESTINATION_COMMIT")
	case Github:
		return "FETCH_HEAD"
	case Gitlab:
		return os.Getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
	case Jenkins:
		bitbucketTargetBranch := os.Getenv("BITBUCKET_TARGET_BRANCH")
		if bitbucketTargetBranch != "" {
			return GetFullBranchName(os.Getenv("BITBUCKET_TARGET_BRANCH"))
		}
		changeTarget := os.Getenv("CHANGE_TARGET")
		if changeTarget != "" {
			return GetFullBranchName(changeTarget)
		}
		return "upstream/master"
	default:
		return "origin/master"
	}
}

func GetFullBranchName(branchName string) string {
	branchPattern := fmt.Sprintf("*/%s", branchName)
	out, err := git.GitExec("branch", "-a", "--list", branchPattern, "--format=%(refname:lstrip=-2)", "--sort=-refname")
	if err != nil {
		log.Logger.Error(errors.Wrap(err, "failed git branch -a"))
	}

	if out != "" {
		branchs := strings.Split(out, "\n")
		if len(branchs) > 0 {
			return branchs[0]
		}
	}
	return fmt.Sprintf("upstream/%s", branchName)
}

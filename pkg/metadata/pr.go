package metadata

import (
	"fmt"
	"os"
	"strings"
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
			return fmt.Sprintf("origin/%s", os.Getenv("BITBUCKET_TARGET_BRANCH"))
		}
		changeTarget := os.Getenv("CHANGE_TARGET")
		if changeTarget != "" {
			return fmt.Sprintf("origin/%s", os.Getenv("CHANGE_TARGET"))
		}
		return "origin/master"
	default:
		return "origin/master"
	}
}

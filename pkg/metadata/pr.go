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
		return os.Getenv("BITBUCKET_TARGET_BRANCH")
	default:
		return "origin/master"
	}
}

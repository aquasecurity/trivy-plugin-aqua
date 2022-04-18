package metadata

import (
	"fmt"
	"os"
	"strings"
)

func GetBaseRef() (r string) {
	buildSystem := GetBuildSystem()
	switch buildSystem {
	case azure:
		return fmt.Sprintf(
			"base/%s",
			strings.ReplaceAll(os.Getenv("SYSTEM_PULLREQUEST_TARGETBRANCH"), "refs/heads/", ""))
	case bitbucket:
		return os.Getenv("BITBUCKET_PR_DESTINATION_COMMIT")
	case github:
		return os.Getenv("FETCH_HEAD")
	case gitlab:
		return os.Getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
	case jenkins:
		return os.Getenv("CHANGE_TARGET")
	default:
		return "origin/master"
	}
}

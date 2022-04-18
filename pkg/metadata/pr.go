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
			"origin/%s",
			strings.ReplaceAll(os.Getenv("SYSTEM_PULLREQUEST_TARGETBRANCH"), "refs/heads/", ""))
	case bitbucket:
		return os.Getenv("BITBUCKET_PR_DESTINATION_COMMIT")
	case github:
		return "FETCH_HEAD"
	case gitlab:
		return os.Getenv("CI_MERGE_REQUEST_DIFF_BASE_SHA")
	case jenkins:
		return fmt.Sprintf("origin/%s", os.Getenv("CHANGE_TARGET"))
	default:
		return "origin/master"
	}
}

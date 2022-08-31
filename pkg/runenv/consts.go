package runenv

const (
	githubCi = "CI"
	githubPr = "GITHUB_BASE_REF"

	bitbucketCi = "CI"
	bitbucketPr = "BITBUCKET_PR_ID"

	gitlabCi = "GITLAB_CI"
	gitlabPr = "CI_MERGE_REQUEST_IID"

	jenkinsCi = "BUILD_TAG"
	jenkinsPr = "CHANGE_TARGET"

	azureCi = "BUILD_BUILDID"
	azurePr = "SYSTEM_PULLREQUEST_PULLREQUESTID"
)

var ciEnvs = []string{githubCi, bitbucketCi, gitlabCi, jenkinsCi, azureCi}

var prEnvs = []string{githubPr, bitbucketPr, gitlabPr, jenkinsPr, azurePr}

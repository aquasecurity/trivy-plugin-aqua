package runenv

const (
	override = "OVERRIDE_BUILDSYSTEM"

	githubCi = "CI"
	githubPr = "GITHUB_BASE_REF"

	bitbucketCi = "CI"
	bitbucketPr = "BITBUCKET_PR_ID"

	gitlabCi = "GITLAB_CI"
	gitlabPr = "CI_MERGE_REQUEST_IID"

	jenkinsCi          = "BUILD_TAG"
	jenkinsPr          = "CHANGE_TARGET"
	jenkinsPrBitbucket = "BITBUCKET_TARGET_BRANCH"

	azureCi = "BUILD_BUILDID"
	azurePr = "SYSTEM_PULLREQUEST_PULLREQUESTID"

	circleciCi = "CI"
	circleciPr = "CIRCLE_PULL_REQUEST"
)

var ciEnvs = []string{githubCi, bitbucketCi, gitlabCi, jenkinsCi, azureCi, circleciCi, override}

var prEnvs = []string{githubPr, bitbucketPr, gitlabPr, jenkinsPr, azurePr, jenkinsPrBitbucket, circleciPr}

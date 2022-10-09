package metadata

const (
	Bitbucket           = "bitbucket"
	Jenkins             = "jenkins"
	Gitlab              = "gitlab"
	Codebuild           = "codebuild"
	Azure               = "azure"
	Github              = "github"
	overrideBuildSystem = "OVERRIDE_BUILDSYSTEM"
	overrideScmId       = "OVERRIDE_SCMID"
)

var possibleRepoEnvVars = []string{
	"OVERRIDE_REPOSITORY",
	"GITHUB_REPOSITORY",
	"BITBUCKET_REPO_SLUG",
	"CI_PROJECT_PATH",
	"CODEBUILD_PROJECT",
	"BUILD_REPOSITORY_NAME",
	"FALLBACK_REPOSITORY",
}

var possibleBranchEnvVars = []string{
	"OVERRIDE_BRANCH",
	"GITHUB_REF_NAME",
	"GIT_BRANCH",
	"BITBUCKET_BRANCH",
	"CI_COMMIT_REF_NAME",
	"CODEBUILD_GIT_BRANCH",
	"BUILD_SOURCEBRANCHNAME",
	"FALLBACK_BRANCH",
}

var possibleCommitIdsEnvVars = []string{
	"BITBUCKET_COMMIT",
	"GITHUB_SHA",
	"GIT_COMMIT",
	"CI_COMMIT_SHA",
	"CODEBUILD_GIT_COMMIT",
}

var possibleBuildSystems = map[string]string{
	"BITBUCKET_COMMIT":     Bitbucket,
	"GIT_COMMIT":           Jenkins,
	"JENKINS_HOME":         Jenkins,
	"CI_COMMIT_SHA":        Gitlab,
	"CODEBUILD_GIT_COMMIT": Codebuild,
	"BUILD_SOURCEBRANCH":   Azure,
	"GITHUB_SHA":           Github,
}

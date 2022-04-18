package metadata

const (
	bitbucket           = "bitbucket"
	jenkins             = "jenkins"
	gitlab              = "gitlab"
	codebuild           = "codebuild"
	azure               = "azure"
	github              = "github"
	overrideBuildSystem = "OVERRIDE_BUILDSYSTEM"
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

var possibleUserEnvVars = []string{
	"GITHUB_ACTOR",
	"CODEBUILD_GIT_AUTHOR",
}

var possibleBuildSystems = map[string]string{
	"BITBUCKET_COMMIT":     bitbucket,
	"GIT_COMMIT":           jenkins,
	"CI_COMMIT_SHA":        gitlab,
	"CODEBUILD_GIT_COMMIT": codebuild,
	"BUILD_SOURCEBRANCH":   azure,
	"GITHUB_SHA":           github,
}

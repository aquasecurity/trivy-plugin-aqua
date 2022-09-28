package metadata

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/argonsecurity/go-environments/models"
	"github.com/pkg/errors"
)

func GetBaseRef(envconfig *models.Configuration) (r string) {
	switch envconfig.Builder {
	case Azure:
		return envconfig.PullRequest.TargetRef.Branch
	case Github, Gitlab:
		return fmt.Sprintf("origin/%s", envconfig.PullRequest.TargetRef.Branch)
	case Bitbucket:
		return envconfig.PullRequest.TargetRef.Branch
	case Jenkins:
		branch := envconfig.PullRequest.TargetRef.Branch
		if branch != "" {
			return branch
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

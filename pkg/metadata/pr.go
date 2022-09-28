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
	if envconfig.Builder == "Jenkins" {
		branch := envconfig.PullRequest.TargetRef.Branch
		if branch != "" {
			return GetFullBranchName(branch, "upstream")
		}
		return "upstream/master"
	}

	if envconfig.PullRequest.TargetRef.Branch != "" {
		return GetFullBranchName(envconfig.PullRequest.TargetRef.Branch, "origin")
	}

	return "origin/master"
}

func GetFullBranchName(branchName, remoteFallback string) string {
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
	return fmt.Sprintf("%s/%s", remoteFallback, branchName)
}

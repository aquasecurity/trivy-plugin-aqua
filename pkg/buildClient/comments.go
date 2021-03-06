package buildClient

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/azure"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/bitbucket"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/github"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/gitlab"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

// prComments send results PR comments
func prComments(buildSystem string, result []*buildsecurity.Result, avdUrlMap ResultIdToUrlMap) error {
	var c = commenter.Repository(nil)
	switch buildSystem {
	case metadata.Github:
		owner, repo, err := getGitHubRepositoryDetails()
		if err != nil {
			return err
		}
		prNumber, err := extractGitHubActionPrNumber()
		if err != nil {
			return err
		}
		r, err := github.NewGithub(os.Getenv("GITHUB_TOKEN"),
			owner,
			repo,
			prNumber)
		if err != nil {
			return err
		}
		c = commenter.Repository(r)
	case metadata.Gitlab:
		r, err := gitlab.NewGitlab(os.Getenv("GITLAB_TOKEN"))
		if err != nil {
			return err
		}
		c = commenter.Repository(r)
	case metadata.Azure:
		r, err := azure.NewAzure(os.Getenv("AZURE_TOKEN"))
		if err != nil {
			return err
		}
		c = commenter.Repository(r)
	case metadata.Bitbucket:
		r, err := bitbucket.NewBitbucket(os.Getenv("BITBUCKET_USER"), os.Getenv("BITBUCKET_TOKEN"))
		if err != nil {
			return err
		}
		c = commenter.Repository(r)
	default:
		return nil
	}

	for _, r := range result {
		if r.SuppressionID == "" {
			switch r.Type {
			case buildsecurity.Result_TYPE_TERRAFORM, buildsecurity.Result_TYPE_CLOUDFORMATION,
				buildsecurity.Result_TYPE_KUBERNETES, buildsecurity.Result_TYPE_DOCKERFILE,
				buildsecurity.Result_TYPE_HCL, buildsecurity.Result_TYPE_YAML:
				err := c.WriteMultiLineComment(r.Filename, returnMisconfMsg(r, avdUrlMap), int(r.StartLine), int(r.EndLine))
				if err != nil {
					return fmt.Errorf("failed write misconfiguration comment: %w", err)
				}

			case buildsecurity.Result_TYPE_SECRETS:
				err := c.WriteMultiLineComment(r.Filename, returnSecretMsg(r), int(r.StartLine), int(r.EndLine))
				if err != nil {
					return fmt.Errorf("failed write secret findings comment: %w", err)
				}
			}
		}
	}
	return nil
}

func returnSecretMsg(r *buildsecurity.Result) string {
	return fmt.Sprintf("### :warning: Aqua detected sensitive data in your code"+
		"  \n**Category:** %s "+
		"  \n**Description:** %s "+
		"  \n**Severity:** %s "+
		"  \n**Match:** %s",
		r.Resource,
		r.Title,
		strings.ReplaceAll(r.Severity.String(), "SEVERITY_", ""),
		r.Message)
}
func returnMisconfMsg(r *buildsecurity.Result, avdUrlMap ResultIdToUrlMap) string {
	commentWithoutAvdUrl := fmt.Sprintf("### :warning: Aqua detected misconfiguration in your code"+
		"  \n**Misconfiguration ID:** %s "+
		"  \n**Check Name:** %s "+
		"  \n**Severity:** %s "+
		"  \n**Message:** %s",
		r.AVDID,
		r.Title,
		strings.ReplaceAll(r.Severity.String(), "SEVERITY_", ""),
		r.Message)

	if avdUrl := avdUrlMap[GenerateResultId(r)]; avdUrl != "" {
		return commentWithoutAvdUrl +
			fmt.Sprintf("  \n  \nRead more at %s",
				avdUrl)
	}

	return commentWithoutAvdUrl
}

func getGitHubRepositoryDetails() (owner, repo string, err error) {
	r := os.Getenv("GITHUB_REPOSITORY")
	s := strings.Split(r, "/")
	if len(s) != 2 {
		return owner, repo,
			fmt.Errorf("failed unexpected value for GITHUB_REPOSITORY."+
				" Expected <organisation/name>, found %v", r)
	}

	return s[0], s[1], nil
}

// extractGitHubActionPrNumber take the pull request number from the GitHub action run
func extractGitHubActionPrNumber() (int, error) {
	githubEventFile := os.Getenv("GITHUB_EVENT_PATH")
	file, err := ioutil.ReadFile(githubEventFile)
	if err != nil {
		return 0, fmt.Errorf("failed gitHub event payload not found in %s", githubEventFile)
	}

	var data interface{}
	err = json.Unmarshal(file, &data)
	if err != nil {
		return 0, err
	}
	payload := data.(map[string]interface{})

	prNumber, err := strconv.Atoi(fmt.Sprintf("%v", payload["number"]))
	if err != nil {
		return 0, fmt.Errorf("failed not a valid PR")
	}
	return prNumber, nil
}

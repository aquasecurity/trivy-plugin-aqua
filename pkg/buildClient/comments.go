package buildClient

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/samber/lo"
	"github.com/sourcegraph/go-diff/diff"

	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/azure"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/bitbucket"
	bitbucket_server "github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/bitbucket-server"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/gitlab"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

const aquaMsg = "[This comment was created by Aqua Pipeline]"

// prComments send results PR comments
func prComments(buildSystem string, result []*buildsecurity.Result, avdUrlMap ResultIdToUrlMap) error {
	var c = commenter.Repository(nil)
	switch buildSystem {
	case metadata.Github:
		r, err := bitbucket_server.NewBitbucketServer(os.Getenv("BITBUCKET_USER"), os.Getenv("BITBUCKET_TOKEN"), "jen", "lior", "27")
		r.PopulateChangeTypes(generateBitbucketFileChanges())

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
	case metadata.Jenkins:
		r, err := bitbucket_server.NewBitbucketServer(os.Getenv("BITBUCKET_USER"), os.Getenv("BITBUCKET_TOKEN"), "jen", "lior", "27")
		r.PopulateChangeTypes(generateBitbucketFileChanges())
		if err != nil {
			return err
		}
		c = commenter.Repository(r)
	default:
		return nil
	}
	err := c.RemovePreviousAquaComments(aquaMsg)
	if err != nil {
		log.Logger.Infof("failed removing old comments with error: %s", err)
	}

	for _, r := range result {
		if r.SuppressionID == "" {
			switch r.Type {
			case buildsecurity.Result_TYPE_TERRAFORM, buildsecurity.Result_TYPE_CLOUDFORMATION,
				buildsecurity.Result_TYPE_KUBERNETES, buildsecurity.Result_TYPE_DOCKERFILE,
				buildsecurity.Result_TYPE_HCL, buildsecurity.Result_TYPE_YAML, buildsecurity.Result_TYPE_PIPELINE:
				err := c.WriteMultiLineComment(r.Filename, returnMisconfMsg(r, avdUrlMap), int(r.StartLine), int(r.EndLine))
				if err != nil {
					log.Logger.Infof("failed write misconfiguration comment: %w", err)
				}
			case buildsecurity.Result_TYPE_VULNERABILITIES:
				if !strings.Contains(r.Filename, "node_modules") {
					err := c.WriteMultiLineComment(r.Filename, returnVulnfMsg(r, avdUrlMap), commenter.FIRST_AVAILABLE_LINE, commenter.FIRST_AVAILABLE_LINE)
					if err != nil {
						log.Logger.Infof("failed write vulnerability comment: %w", err)
					}
				}

			case buildsecurity.Result_TYPE_SECRETS:
				err := c.WriteMultiLineComment(r.Filename, returnSecretMsg(r), int(r.StartLine), int(r.EndLine))
				if err != nil {
					log.Logger.Infof("failed write secret findings comment: %w", err)
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
		"  \n**Match:** %s"+
		"  \n%s",
		r.Resource,
		r.Title,
		strings.ReplaceAll(r.Severity.String(), "SEVERITY_", ""),
		r.Message,
		aquaMsg)
}

func returnMisconfMsg(r *buildsecurity.Result, avdUrlMap ResultIdToUrlMap) string {
	commentWithoutAvdUrl := fmt.Sprintf("### :warning: Aqua detected misconfiguration in your code"+
		"  \n**Misconfiguration ID:** %s "+
		"  \n**Check Name:** %s "+
		"  \n**Severity:** %s "+
		"  \n**Message:** %s"+
		"  \n%s",
		r.AVDID,
		r.Title,
		strings.ReplaceAll(r.Severity.String(), "SEVERITY_", ""),
		r.Message,
		aquaMsg)

	if avdUrl := avdUrlMap[GenerateResultId(r)]; avdUrl != "" {
		return commentWithoutAvdUrl +
			fmt.Sprintf("  \n  \nRead more at %s",
				avdUrl)
	}

	return commentWithoutAvdUrl
}

func returnVulnfMsg(r *buildsecurity.Result, avdUrlMap ResultIdToUrlMap) string {
	commentWithoutAvdUrl := fmt.Sprintf("### :warning: Aqua detected vulnerability in your code"+
		"  \n**Vulnerability ID:** %s "+
		"  \n**Check Name:** %s "+
		"  \n**Severity:** %s "+
		"  \n**Fixed Version:** %s "+
		"  \n**Description:** %s"+
		"  \n%s",
		r.AVDID,
		r.Title,
		strings.ReplaceAll(r.Severity.String(), "SEVERITY_", ""),
		r.FixedVersion,
		r.Message,
		aquaMsg)

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
	file, err := os.ReadFile(githubEventFile)
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

func generateBitbucketFileChanges() bitbucket_server.FileToChanges {
	fileToChanges := make(bitbucket_server.FileToChanges)
	out, _ := git.GitExec("diff", metadata.GetBaseRef())
	diff, _ := diff.ParseMultiFileDiff([]byte(out))
	for _, fileDiff := range diff {
		filename := fileDiff.NewName
		changes := make(bitbucket_server.FileChanges, 0)
		for _, hunk := range fileDiff.Hunks {
			linesChange := hunk.NewLines - hunk.OrigLines
			change := bitbucket_server.FileChange{
				StartLine:  int(hunk.NewStartLine),
				EndLine:    int(hunk.NewStartLine + hunk.NewLines - 1),
				ChangeType: lo.Ternary(linesChange > 0, "ADDED", lo.Ternary(linesChange < 0, "REMOVED", "CONTEXT")),
			}
			changes = append(changes, change)
		}
		fileToChanges[filename] = changes
	}
	return fileToChanges
}

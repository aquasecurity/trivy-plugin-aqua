package buildClient

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/argonsecurity/go-environments/models"

	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/azure"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/bitbucket"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/github"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/gitlab"
	"github.com/aquasecurity/go-git-pr-commenter/pkg/commenter/jenkins"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/argonsecurity/go-environments/enums"
)

const AQUA_MSG = "[This comment was created by Aqua Pipeline]"

// prComments send results PR comments
func prComments(envconfig *models.Configuration, result []*buildsecurity.Result, avdUrlMap ResultIdToUrlMap) error {
	c, source, err := getCommenter(envconfig)
	if err != nil {
		return err
	}

	if c == nil {
		return fmt.Errorf("couldnt initialize provider client")
	}

	log.Logger.Debugf("Removing previous aqua comments from %s", source)
	if err := c.RemovePreviousAquaComments(AQUA_MSG); err != nil {
		log.Logger.Infof("failed removing old comments with error: %s", err)
	}

	log.Logger.Debugf("Writing comments to %s", source)
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
					msg := returnVulnfMsg(r, avdUrlMap)
					err := c.WriteMultiLineComment(r.Filename, msg, int(r.StartLine), int(r.EndLine))
					if err != nil {
						log.Logger.Debugf("failed write vulnerability comment, retrying on first available line...")
						err := c.WriteMultiLineComment(r.Filename, msg, commenter.FIRST_AVAILABLE_LINE, commenter.FIRST_AVAILABLE_LINE)
						if err != nil {
							log.Logger.Infof("failed write vulnerability comment: %w", err)
						}
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

func getCommenter(envconfig *models.Configuration) (commenter.Repository, enums.Source, error) {
	var c commenter.Repository
	source := envconfig.Repository.Source

	if strings.ToLower(envconfig.Builder) == string(enums.Jenkins) {
		r, err := jenkins.NewJenkins(metadata.GetBaseRef(envconfig))
		if err != nil {
			return nil, "", err
		}

		c = r
		return c, source, nil
	}

	switch source {
	case enums.Github:
		prNumber, err := extractGitHubPrNumber(envconfig.Builder, envconfig.PullRequest.Id)
		if err != nil {
			return nil, "", err
		}
		r, err := github.NewGithub(os.Getenv("GITHUB_TOKEN"),
			envconfig.Organization.Name,
			envconfig.Repository.Name,
			prNumber)
		if err != nil {
			return nil, "", err
		}
		c = commenter.Repository(r)
	case enums.GithubServer:
		prNumber, err := extractGitHubPrNumber(envconfig.Builder, envconfig.PullRequest.Id)
		if err != nil {
			return nil, "", err
		}
		parsedUrl, err := url.Parse(envconfig.Repository.CloneUrl)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse clone parsedUrl %s - %s", envconfig.Repository.CloneUrl, err.Error())
		}

		r, err := github.NewGithubServer(fmt.Sprintf("%s://%s", parsedUrl.Scheme, parsedUrl.Host),
			os.Getenv("GITHUB_TOKEN"),
			envconfig.Organization.Name,
			envconfig.Repository.Name,
			prNumber)
		if err != nil {
			return nil, "", err
		}
		c = commenter.Repository(r)
	case enums.Gitlab, enums.GitlabServer:
		r, err := gitlab.NewGitlab(os.Getenv("GITLAB_TOKEN"))
		if err != nil {
			return nil, "", err
		}
		c = commenter.Repository(r)
	case enums.Azure:
		r, err := azure.NewAzure(os.Getenv("AZURE_TOKEN"))
		if err != nil {
			return nil, "", err
		}
		c = commenter.Repository(r)
	case enums.Bitbucket:
		r, err := bitbucket.NewBitbucket(os.Getenv("BITBUCKET_USER"), os.Getenv("BITBUCKET_TOKEN"))
		if err != nil {
			return nil, "", err
		}
		c = commenter.Repository(r)
	default:
		return nil, "", fmt.Errorf("unsupported source: %s", source)
	}

	return c, source, nil
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
		AQUA_MSG)
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
		AQUA_MSG)

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
		AQUA_MSG)

	if avdUrl := avdUrlMap[GenerateResultId(r)]; avdUrl != "" {
		return commentWithoutAvdUrl +
			fmt.Sprintf("  \n  \nRead more at %s",
				avdUrl)
	}

	return commentWithoutAvdUrl
}

// extractGitHubPrNumber take the pull request number from the GitHub action run
func extractGitHubPrNumber(builder string, prId string) (int, error) {
	if strings.ToLower(builder) == string(enums.CircleCi) {
		convertedPrNumber, err := strconv.Atoi(prId)
		if err != nil {
			return 0, err
		}
		return convertedPrNumber, nil

	}

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

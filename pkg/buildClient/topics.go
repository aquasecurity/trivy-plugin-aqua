package buildClient

import (
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient/scm"
	"github.com/argonsecurity/go-environments/enums"
	"github.com/argonsecurity/go-environments/models"
)

func getTopics(envConfig *models.Configuration) ([]string, error) {
	switch envConfig.Repository.Source {
	case enums.Github, enums.GithubServer:
		owner := envConfig.Organization.Name
		repo := envConfig.Repository.Name

		client := scm.GetGitHubClient(envConfig)
		topics, _, err := client.ListRepositoryTopics(owner, repo)
		if err != nil {
			return nil, err
		}
		return topics, nil
	}
	return []string{}, nil
}

package buildClient

import (
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient/scm"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
)

func getTopics(buildSystem string) ([]string, error) {
	switch buildSystem {
	case metadata.Github:
		{
			owner, repo, err := getGitHubRepositoryDetails()
			if err != nil {
				return nil, err
			}

			client := scm.GetGitHubClient()
			topics, _, err := client.ListRepositoryTopics(owner, repo)
			if err != nil {
				return nil, err
			}
			return topics, nil
		}
	}
	return []string{}, nil
}

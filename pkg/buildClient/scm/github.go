package scm

import (
	"context"
	"net/http"
	"os"

	"github.com/google/go-github/v38/github"
	"golang.org/x/oauth2"
)

var (
	Client GithubClient
)

type GithubClient interface {
	ListRepositoryTopics(owner, repo string) ([]string, *github.Response, error)
}

type GithubClientImpl struct {
	ctx    context.Context
	client *github.Client
}

func GetGitHubClient() GithubClient {
	ctx, client := getGithubClient(os.Getenv("GITHUB_TOKEN"), os.Getenv("GITHUB_API_URL"))
	Client = &GithubClientImpl{ctx: ctx, client: client}
	return Client
}

func getGithubClient(token, baseUrl string) (context.Context, *github.Client) {
	var tc *http.Client
	ctx := context.Background()
	if token != "" {

		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc = oauth2.NewClient(ctx, ts)
	}

	client, _ := github.NewEnterpriseClient(baseUrl, baseUrl, tc)
	return ctx, client
}

func (gca *GithubClientImpl) ListRepositoryTopics(owner, repo string) ([]string, *github.Response, error) {
	return gca.client.Repositories.ListAllTopics(gca.ctx, owner, repo)
}

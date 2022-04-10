package buildClient

import (
	"context"
	"fmt"
	"github.com/urfave/cli/v2"
	"net/http"
	"os"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/pkg/errors"
	"github.com/twitchtv/twirp"
)

type Client interface {
	Upload([]*buildsecurity.Result, map[string]string) error
	GetPoliciesForRepository() ([]*buildsecurity.Policy, error)
	GetOrCreateRepository() (string, error)
}

type TwirpClient struct {
	client   buildsecurity.BuildSecurity
	c        *cli.Context
	scanPath string
	jwtToken string
	aquaUrl  string
	repoId   string
}

var buildClient Client

func Get(scanPath string, c *cli.Context) (Client, error) {
	if buildClient != nil {
		log.Logger.Debugf("Valid client found, re-using...")
		return buildClient, nil
	}

	cspmURL, ok := os.LookupEnv("CSPM_URL")
	if !ok {
		cspmURL = "https://api.cloudsploit.com/v2/tokens"
	}

	aquaURL, ok := os.LookupEnv("AQUA_URL")
	if !ok {
		aquaURL = "https://api.aquasec.com/v2/build"
	}

	aquaKey, ok := os.LookupEnv("AQUA_KEY")
	if !ok {
		return nil, fmt.Errorf("could not find the AQUA_KEY environment variable")
	}

	aquaSecret, ok := os.LookupEnv("AQUA_SECRET")
	if !ok {
		return nil, fmt.Errorf("could not find the AQUA_SECRET environment variable")
	}

	log.Logger.Debugf("Logging in to CSPM")
	jwtToken, err := obtainJWT(aquaKey, aquaSecret, cspmURL)
	if err != nil {
		return nil, errors.Wrap(err, "failed generating temporary JWT token")
	}
	log.Logger.Debugf("Successfully logged in, creating client")
	client := buildsecurity.NewBuildSecurityProtobufClient(aquaURL, &http.Client{})

	buildClient = &TwirpClient{
		client:   client,
		scanPath: scanPath,
		jwtToken: jwtToken,
		aquaUrl:  aquaURL,
		c:        c,
	}

	return buildClient, nil
}

func (bc *TwirpClient) createContext() (context.Context, error) {
	ctx := context.Background()

	header := make(http.Header)
	header.Set("Authorization", fmt.Sprintf("Bearer %s", bc.jwtToken))

	ctx, err := twirp.WithHTTPRequestHeaders(ctx, header)
	if err != nil {
		return nil, err
	}

	return ctx, nil
}

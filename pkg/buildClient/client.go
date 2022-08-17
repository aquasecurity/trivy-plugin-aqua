package buildClient

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/pkg/errors"
	"github.com/twitchtv/twirp"
)

type Client interface {
	Upload([]*buildsecurity.Result, map[string]string, ResultIdToUrlMap, []*buildsecurity.Pipeline) error
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

type ResultIdToUrlMap map[string]string

func GenerateResultId(r *buildsecurity.Result) string {
	return fmt.Sprintf("%d_%s", r.Type, r.AVDID)
}

var buildClient Client

func Get(scanPath string, c *cli.Context) (Client, error) {
	if buildClient != nil {
		log.Logger.Debugf("Valid client found, re-using...")
		return buildClient, nil
	}

	cspmURL, aquaURL := getCspmAndAquaUrl()

	aquaKey, ok := os.LookupEnv("AQUA_KEY")
	if !ok {
		return nil, fmt.Errorf("could not find the AQUA_KEY environment variable")
	}

	aquaSecret, ok := os.LookupEnv("AQUA_SECRET")
	if !ok {
		return nil, fmt.Errorf("could not find the AQUA_SECRET environment variable")
	}

	if aquaKey == "" || aquaSecret == "" {
		return nil, fmt.Errorf("could not continue with empty value for AQUA_KEY or AQUA_SECRET environment variables")
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

func getCspmAndAquaUrl() (string, string) {
	var urlPrefix string
	awsRegion, _ := os.LookupEnv("AWS_REGION")
	switch awsRegion {
	case "eu-central-1":
		urlPrefix = "eu-1."
	case "ap-southeast-1":
		urlPrefix = "asia-1."
	// us-east-1, or any unknown
	default:
		urlPrefix = ""
	}

	cspmURL, ok := os.LookupEnv("CSPM_URL")
	if !ok {
		cspmURL = fmt.Sprintf("https://%sapi.cloudsploit.com/v2/tokens", urlPrefix)
	}

	aquaURL, ok := os.LookupEnv("AQUA_URL")
	if !ok {
		aquaURL = fmt.Sprintf("https://%sapi.aquasec.com/v2/build", urlPrefix)
	}

	return cspmURL, aquaURL
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

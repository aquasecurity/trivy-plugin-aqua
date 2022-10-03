package buildClient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/pkg/errors"
	"github.com/twitchtv/twirp"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/flag"
)

type Client interface {
	Upload([]*buildsecurity.Result, map[string]string, ResultIdToUrlMap, []*buildsecurity.Pipeline, map[string]*buildsecurity.PackageDependencies) error
	GetPoliciesForRepository() ([]*buildsecurity.Policy, error)
	UpsertRepository() (string, error)
}

type TwirpClient struct {
	client   buildsecurity.BuildSecurity
	cmdName  string
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

func Get(scanPath, cmdName string, opts flag.Options) (Client, error) {
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
		cmdName:  cmdName,
	}

	return buildClient, nil
}

func getBaseUrl(inputUrl string) (string, error) {
	u, err := url.ParseRequestURI(inputUrl)
	if err != nil {
		return "", err
	}
	return u.Scheme + "://" + u.Host, nil
}

func getUrlWithRoute(url, route, fallbackUrl string) string {
	baseUrl, err := getBaseUrl(url)
	if url == "" || err != nil {
		return fallbackUrl
	} else {
		return fmt.Sprintf("%s%s", baseUrl, route)
	}
}

func getCspmAndAquaUrl() (string, string) {

	cspmURL := getUrlWithRoute(os.Getenv("CSPM_URL"), "/v2/tokens", "https://api.cloudsploit.com/v2/tokens")
	aquaURL := getUrlWithRoute(os.Getenv("AQUA_URL"), "/v2/build", "https://api.aquasec.com/v2/build")

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

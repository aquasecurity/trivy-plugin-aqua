package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	fs "github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-plugin-aqua/internal"
	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
)

const (
	// TODO: fix me
	remoteAddr = "https://aquasec.com/xxx"
)

var (
	version = "dev"
)

func main() {
	app := newApp(version)
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func newApp(version string) *cli.App {
	app := cli.NewApp()
	app.Name = "Aqua"
	app.Version = version
	app.ArgsUsage = "target"
	app.Usage = "Aqua plugin"
	app.EnableBashCompletion = true

	// TODO(teppei): fix me
	app.Flags = nil

	// Config scanning
	configCommand := commands.NewConfigCommand()
	configCommand.Flags = append(configCommand.Flags,
		&cli.StringFlag{
			Name:     "key",
			Usage:    "key",
			Required: true,
		},
		&cli.StringFlag{
			Name:     "secret",
			Usage:    "secret",
			Required: true,
		},
	)
	configCommand.Action = run

	app.Commands = append(app.Commands, configCommand)

	return app
}

func run(ctx *cli.Context) error {
	opt, err := artifact.NewOption(ctx)
	if err != nil {
		return err
	}

	jwtToken, err := obtainJWT(ctx.String("key"), ctx.String("secret"))
	if err != nil {
		return err
	}

	headers := customHeaders(jwtToken)
	policyDir, dataDir := downloadCustomPolicies(jwtToken)

	initializeScanner := initializeFilesystemScanner(ctx.Args().First(), policyDir, dataDir, headers)

	return artifact.Run(opt, initializeScanner, initAquaCache(headers))
}

func downloadCustomPolicies(jwtToken string) (string, string) {
	// TODO: fix me
	// Not implemented yet
	policyDir := "/tmp/policies"
	dataDir := "/tmp/data"
	return policyDir, dataDir
}

func obtainJWT(key, secret string) (string, error) {
	var Response struct {
		Status  int    `json:"status"`
		Message int    `json:"message"`
		Data    string `json:"data"`
	}

	aquaApi := "https://api.cloudsploit.com/v2/tokens"
	body := `{"validity":10,"allowed_endpoints":["ANY:vs/v2/scan"]}`

	req, err := http.NewRequest("POST", aquaApi, bytes.NewBuffer([]byte(body)))
	if err != nil {
		return "", err
	}

	timestampString := strconv.Itoa(int(time.Now().Unix()))
	someString := timestampString + "POST/v2/tokens" + body
	signature := internal.ComputeHmac256(someString, secret)

	req.Header.Add("x-signature", signature)
	req.Header.Add("x-timestamp", timestampString)
	req.Header.Add("x-api-key", key)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer resp.Body.Close()

	json.NewDecoder(resp.Body).Decode(&Response)
	if Response.Status != 200 && Response.Data != "" {
		return "", fmt.Errorf("failed to generate Aqua token with error: %v", Response.Message)
	}
	return Response.Data, nil
}

func customHeaders(jwtToken string) http.Header {
	result := make(http.Header)

	result.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))
	return result
}

func initAquaCache(customHeaders http.Header) artifact.InitCache {
	return func(c artifact.Option) (cache.Cache, error) {
		return NewAquaCache(remoteAddr, customHeaders), nil
	}
}

func initializeFilesystemScanner(dir, customPolicyDir, customDataDir string, customHeaders http.Header) artifact.InitializeScanner {
	return func(ctx context.Context, target string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache,
		timeout time.Duration, disabledAnalyzers []analyzer.Type, configScannerOption config.ScannerOption) (
		scanner.Scanner, func(), error) {

		// Merge customer's policies/data and local policies/data
		configScannerOption.PolicyPaths = append(configScannerOption.PolicyPaths, customPolicyDir)
		configScannerOption.DataPaths = append(configScannerOption.DataPaths, customDataDir)

		protobufClient := client.NewProtobufClient(remoteAddr)
		remoteScanner := client.NewScanner(client.CustomHeaders(customHeaders), protobufClient)
		fsScanner := fs.NewArtifact(dir, artifactCache, nil, configScannerOption)

		return scanner.NewScanner(remoteScanner, fsScanner), func() {}, nil
	}
}

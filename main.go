package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/aquasecurity/trivy-plugin-aqua/internal"
	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/urfave/cli/v2"

	fs "github.com/aquasecurity/fanal/artifact/local"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/rpc/client"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
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

	app.Commands = cli.Commands{
		{
			Name:   "iac",
			Action: run,
			Flags: []cli.Flag{
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
				&cli.StringSliceFlag{
					Name:     "policy",
					Usage:    "policy",
					Required: true,
					Value:    cli.NewStringSlice("policy"),
				},
			},
		},
	}

	return app
}

func run(ctx *cli.Context) error {
	jwtToken, err := obtainJWT(ctx.String("key"), ctx.String("secret"))
	if err != nil {
		return err
	}

	headers := customHeaders(jwtToken)

	policyDir := downloadCustomPolicies(jwtToken)

	s := initializeFilesystemScanner(ctx, policyDir, headers)
	option := types.ScanOptions{
		SecurityChecks: []types.SecurityCheck{types.SecurityCheckIaC},
	}

	results, err := s.ScanArtifact(ctx.Context, option)
	if err != nil {
		return err
	}

	// TODO: fix me
	severities := []dbTypes.Severity{dbTypes.SeverityCritical, dbTypes.SeverityHigh}
	err = report.WriteResults("table", os.Stdout, severities, results, "", false)
	if err != nil {
		return err
	}

	return nil
}

func downloadCustomPolicies(jwtToken string) string {
	// TODO: fix me
	// Not implemented yet
	policyDir := "/tmp"
	return policyDir
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

func customHeaders(jwtToken string) client.CustomHeaders {
	result := make(http.Header)

	result.Set("Authorization", fmt.Sprintf("Bearer %s", jwtToken))
	return client.CustomHeaders(result)
}

func initializeFilesystemScanner(ctx *cli.Context, customPolicyDir string, customHeaders client.CustomHeaders) scanner.Scanner {
	dir := ctx.Args().First()

	// Merge customer's policies and local policies
	policyDirs := ctx.StringSlice("policy")
	policyDirs = append(policyDirs, customPolicyDir)
	cache := NewWaveCache(policyDirs)

	remoteAddr := ctx.String("remote")
	protobufClient := client.NewProtobufClient(client.RemoteURL(remoteAddr))

	remoteScanner := client.NewScanner(customHeaders, protobufClient)

	fsScanner := fs.NewArtifact(dir, cache, nil)
	return scanner.NewScanner(remoteScanner, fsScanner)
}

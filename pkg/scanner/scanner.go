package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	fanalconfig "github.com/aquasecurity/fanal/analyzer/config"
	fanalartifact "github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

const (
	policyDir   = "/tmp/policies"
	dataDir     = "/tmp/data"
	resultsFile = "results.json"
)

func Scan(c *cli.Context, path string) (report.Results, error) {

	initializeScanner := initializeFilesystemScanner(path, policyDir, dataDir)

	opt, err := createScanOptions(c)
	if err != nil {
		return nil, errors.Wrap(err, "failed creating scan options")
	}

	err = artifact.Run(c.Context, opt, initializeScanner, initAquaCache())
	if err != nil {
		return nil, errors.Wrap(err, "failed running scan")
	}

	_, err = os.Stat(resultsFile)
	if err != nil {
		return nil, errors.Wrap(err, "results file does not exist")
	}

	jsonFile, err := os.Open(resultsFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed opening results file")
	}
	defer func() { _ = jsonFile.Close() }()

	var buf bytes.Buffer
	_, err = io.Copy(&buf, jsonFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed reading results file")
	}

	var results report.Results
	err = json.Unmarshal(buf.Bytes(), &results)
	if err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling results file")
	}

	return results, nil

}

func initializeFilesystemScanner(dir, _, _ string) artifact.InitializeScanner {
	return func(_ context.Context, _ string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, _ time.Duration, option fanalartifact.Option, configScannerOption fanalconfig.ScannerOption) (scanner.Scanner, func(), error) {

		fs, err := local.NewArtifact(dir, artifactCache, option, configScannerOption)
		if err != nil {
			return scanner.Scanner{}, func() {}, err
		}

		lscanner := newAquaScanner(localArtifactCache)

		return scanner.NewScanner(lscanner, fs), func() {}, nil
	}
}

func createScanOptions(c *cli.Context) (artifact.Option, error) {

	opt, err := artifact.NewOption(c)
	if err != nil {
		return opt, err
	}

	// initialize options
	if err = opt.Init(); err != nil {
		return opt, fmt.Errorf("failed initializing options: %w", err)
	}

	return opt, nil
}

func MatchResultSeverity(severity string) buildsecurity.SeverityEnum {
	severity = fmt.Sprintf("SEVERITY_%s", severity)
	index := buildsecurity.SeverityEnum_value[severity]
	return buildsecurity.SeverityEnum(index)
}

func MatchResultType(resultType string) buildsecurity.Result_TypeEnum {
	resultType = strings.ToUpper(fmt.Sprintf("TYPE_%s", resultType))
	index := buildsecurity.Result_TypeEnum_value[resultType]
	return buildsecurity.Result_TypeEnum(index)
}

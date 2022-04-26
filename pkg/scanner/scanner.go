package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"golang.org/x/xerrors"
	"io"
	"os"
	"strings"

	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"

	fanalartifact "github.com/aquasecurity/fanal/artifact"
	image2 "github.com/aquasecurity/fanal/artifact/image"
	fanalartifactlocal "github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/scanner"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
)

const (
	policyDir   = "/tmp/policies"
	dataDir     = "/tmp/data"
	resultsFile = "results.json"
	aquaPath    = "/tmp/aqua"
)

func Scan(c *cli.Context, path string) (trivyTypes.Results, error) {
	var initializeScanner artifact.InitializeScanner
	switch c.Command.Name {
	case "image":
		initializeScanner = imageScanner(path)
	default:
		if c.String("triggered-by") == "PR" {
			err := createDiffScanFs()
			if err != nil {
				return nil, errors.Wrap(err, "failed create diff scan system")
			}
			path = aquaPath
		}
		initializeScanner = filesystemStandaloneScanner(path)
	}

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

	var results trivyTypes.Results
	err = json.Unmarshal(buf.Bytes(), &results)
	if err != nil {
		return nil, errors.Wrap(err, "failed unmarshaling results file")
	}

	// Cleanup tmp diff dir
	defer os.RemoveAll(aquaPath)

	return results, nil

}

// imageScanner initializes a container image scanner in standalone mode
func imageScanner(path string) artifact.InitializeScanner {
	return func(ctx context.Context, conf artifact.ScannerConfig) (scanner.Scanner, func(), error) {
		dockerOpt, err := trivyTypes.GetDockerOption(conf.ArtifactOption.InsecureSkipTLS)
		if err != nil {
			return scanner.Scanner{}, nil, err
		}
		s, cleanup, err := initializeDockerScanner(ctx, path, conf.ArtifactCache, conf.LocalArtifactCache,
			dockerOpt, conf.ArtifactOption)
		if err != nil {
			return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a docker scanner: %w", err)
		}
		return s, cleanup, nil
	}
}

func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, dockerOpt types.DockerOption, artifactOption fanalartifact.Option) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	detector := ospkg.Detector{}
	localScanner := local.NewScanner(applierApplier, detector)
	typesImage, cleanup, err := image.NewDockerImage(ctx, imageName, dockerOpt)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	artifactArtifact, err := image2.NewArtifact(typesImage, artifactCache, artifactOption)
	if err != nil {
		cleanup()
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
		cleanup()
	}, nil
}

func filesystemStandaloneScanner(path string) artifact.InitializeScanner {
	return func(ctx context.Context, config artifact.ScannerConfig) (scanner.Scanner, func(), error) {
		s, cleanup, err := initializeFilesystemScanner(ctx, path, config.ArtifactCache, config.LocalArtifactCache, fanalartifact.Option{})
		if err != nil {
			return scanner.Scanner{}, func() {}, xerrors.Errorf("unable to initialize a filesystem scanner: %w", err)
		}
		return s, cleanup, nil
	}
}

// initializeFilesystemScanner is for filesystem scanning in standalone mode
func initializeFilesystemScanner(_ context.Context, path string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, artifactOption fanalartifact.Option) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	detector := ospkg.Detector{}
	localScanner := local.NewScanner(applierApplier, detector)
	artifactArtifact, err := fanalartifactlocal.NewArtifact(path, artifactCache, artifactOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
	}, nil
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

func MatchTriggeredBy(triggeredBy string) buildsecurity.TriggeredByEnum {
	triggeredBy = fmt.Sprintf("TRIGGERED_BY_%s", triggeredBy)
	index := buildsecurity.TriggeredByEnum_value[triggeredBy]
	return buildsecurity.TriggeredByEnum(index)
}

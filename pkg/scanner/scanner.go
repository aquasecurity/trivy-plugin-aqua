package scanner

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"os"

	"path/filepath"
	"strings"

	"github.com/liamg/memoryfs"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/pipelines"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	ppConsts "github.com/argonsecurity/pipeline-parser/pkg/consts"

	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

const aquaPath = "/tmp/aqua"
const policiesPath = "/Users/tamirkiviti/Argon/trivy-plugin-aqua/pkg/pipelines/policies/policy.rego"

//go:embed trivy-secret.yaml
var secretsConfig string

func Scan(c *cli.Context, path string) (*trivyTypes.Report, []*buildsecurity.Pipeline, error) {
	err := os.MkdirAll(aquaPath, os.ModePerm)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed create aqua tmp dir")
	}
	// Cleanup aqua tmp dir
	defer os.RemoveAll(aquaPath)

	ctx := c.Context
	opt, err := artifact.InitOption(c)
	if err != nil {
		return nil, nil, err
	}

	if slices.Contains(opt.SecurityChecks, trivyTypes.SecurityCheckSecret) {
		configPath := filepath.Join(aquaPath, "trivy-secret.yaml")
		if err = os.WriteFile(configPath, []byte(secretsConfig), 0600); err != nil {
			return nil, nil, errors.Wrap(err, "failed creating secret config file")
		}
		opt.SecretOption.SecretConfigPath = configPath
	}

	r, err := artifact.NewRunner(opt)
	if err != nil {
		return nil, nil, xerrors.Errorf("init error: %w", err)
	}
	defer r.Close(ctx)

	repositoryPipelines := make([]*buildsecurity.Pipeline, 0)
	var report trivyTypes.Report
	switch c.Command.Name {
	case "image":
		opt.Target = path
		// Container image scanning
		if report, err = r.ScanImage(ctx, opt); err != nil {
			return nil, nil, xerrors.Errorf("image scan error: %w", err)
		}
	default:
		if c.String("triggered-by") == "PR" {
			if err = createDiffScanFs(); err != nil {
				return nil, nil, errors.Wrap(err, "failed create diff scan system")
			}
			opt.Target = aquaPath
		}

		if c.Bool("pipelines") {
			repositoryPipelines, files, sourcesMap, err := pipelines.GetPipelines(path)
			if err != nil {
				return nil, nil, errors.Wrap(err, "failed get pipelines")
			}
			pipelineMisconfigurations, err := ScanPipelines(ctx, repositoryPipelines, files, sourcesMap)
			fmt.Println(pipelineMisconfigurations)
			if err != nil {
				return nil, nil, errors.Wrap(err, "failed scan pipelines")
			}
		}

		// Filesystem scanning
		if report, err = r.ScanFilesystem(ctx, opt); err != nil {
			return nil, nil, xerrors.Errorf("image scan error: %w", err)
		}
	}

	report, err = r.Filter(ctx, opt, report)
	if err != nil {
		return nil, nil, xerrors.Errorf("filter error: %w", err)
	}

	if err = r.Report(opt, report); err != nil {
		return nil, nil, xerrors.Errorf("report error: %w", err)
	}
	return &report, repositoryPipelines, nil
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

func CreateMemoryFs(files []types.File) (*memoryfs.FS, error) {
	memFs := memoryfs.New()

	for _, file := range files {
		if filepath.Dir(file.Path) != "." {
			if err := memFs.MkdirAll(filepath.Dir(file.Path), os.ModePerm); err != nil {
				return nil, xerrors.Errorf("memoryfs mkdir error: %w", err)
			}
		}
		if err := memFs.WriteFile(file.Path, file.Content, os.ModePerm); err != nil {
			return nil, xerrors.Errorf("memoryfs write error: %w", err)
		}
	}
	return memFs, nil
}

func ScanPipelines(ctx context.Context, repositoryPipelines []*buildsecurity.Pipeline, files []types.File, sourcesMap map[string]ppConsts.Platform) ([]*trivyTypes.DetectedMisconfiguration, error) {
	f, err := os.Open(filepath.ToSlash(policiesPath))
	if err != nil {
		return nil, errors.Wrap(err, "failed read policies")
	}
	memFs, err := CreateMemoryFs(files)
	if err != nil {
		return nil, errors.Wrap(err, "failed create memory fs")
	}
	pipelineScanner := pipelines.NewScanner()
	pipelineScanner.SetPolicyReaders([]io.Reader{f})

	mis, err := pipelineScanner.ScanFS(context.WithValue(ctx, "sourcesMap", sourcesMap), memFs, "/")
	fmt.Println(mis)
	return nil, nil
}

package scanner

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/pipelines"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

const aquaPath = "/tmp/aqua"

//go:embed trivy-secret.yaml
var secretsConfig string

func Scan(ctx context.Context, opts flag.Options, cmdName, path string) (*trivyTypes.Report, []*buildsecurity.Pipeline, error) {
	err := os.MkdirAll(aquaPath, os.ModePerm)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed create aqua tmp dir")
	}
	// Cleanup aqua tmp dir
	defer os.RemoveAll(aquaPath)

	if slices.Contains(opts.SecurityChecks, trivyTypes.SecurityCheckSecret) {
		configPath := filepath.Join(aquaPath, "trivy-secret.yaml")
		if err = os.WriteFile(configPath, []byte(secretsConfig), 0600); err != nil {
			return nil, nil, errors.Wrap(err, "failed creating secret config file")
		}
		opts.SecretOptions.SecretConfigPath = configPath
	}

	r, err := artifact.NewRunner(ctx, opts)
	if err != nil {
		return nil, nil, xerrors.Errorf("init error: %w", err)
	}
	defer r.Close(ctx)

	repositoryPipelines := make([]*buildsecurity.Pipeline, 0)
	var report trivyTypes.Report
	switch cmdName {
	case "image":
		opts.Target = path
		// Container image scanning
		if report, err = r.ScanImage(ctx, opts); err != nil {
			return nil, nil, xerrors.Errorf("image scan error: %w", err)
		}
	default:
		if viper.GetString("triggered-by") == "PR" {
			if err = createDiffScanFs(); err != nil {
				return nil, nil, errors.Wrap(err, "failed create diff scan system")
			}
			opts.Target = aquaPath
		}

		if viper.GetBool("pipelines") {
			repositoryPipelines, err = pipelines.GetPipelines(path)
			if err != nil {
				return nil, nil, errors.Wrap(err, "failed get pipelines")
			}
		}
		// Filesystem scanning
		if report, err = r.ScanFilesystem(ctx, opts); err != nil {
			return nil, nil, xerrors.Errorf("image scan error: %w", err)
		}
	}

	report, err = r.Filter(ctx, opts, report)
	if err != nil {
		return nil, nil, xerrors.Errorf("filter error: %w", err)
	}

	if err = r.Report(opts, report); err != nil {
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

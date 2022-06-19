package scanner

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

const aquaPath = "/tmp/aqua"

//go:embed trivy-secret.yaml
var secretsConfig string

func Scan(c *cli.Context, path string) (trivyTypes.Results, error) {
	err := os.MkdirAll(aquaPath, os.ModePerm)
	if err != nil {
		return nil, errors.Wrap(err, "failed create aqua tmp dir")
	}
	// Cleanup aqua tmp dir
	defer os.RemoveAll(aquaPath)

	ctx := c.Context
	opt, err := artifact.InitOption(c)
	if err != nil {
		return nil, err
	}

	if slices.Contains(opt.SecurityChecks, trivyTypes.SecurityCheckSecret) {
		configPath := filepath.Join(aquaPath, "trivy-secret.yaml")
		if err = os.WriteFile(configPath, []byte(secretsConfig), 0600); err != nil {
			return nil, errors.Wrap(err, "failed creating secret config file")
		}
		opt.SecretOption.SecretConfigPath = configPath
	}

	r, err := artifact.NewRunner(opt)
	if err != nil {
		return nil, xerrors.Errorf("init error: %w", err)
	}
	defer r.Close(ctx)

	var report trivyTypes.Report
	switch c.Command.Name {
	case "image":
		opt.Target = path
		// Container image scanning
		if report, err = r.ScanImage(ctx, opt); err != nil {
			return nil, xerrors.Errorf("image scan error: %w", err)
		}
	default:
		if c.String("triggered-by") == "PR" {
			if err = createDiffScanFs(); err != nil {
				return nil, errors.Wrap(err, "failed create diff scan system")
			}
			opt.Target = aquaPath
		}
		// Filesystem scanning
		if report, err = r.ScanFilesystem(ctx, opt); err != nil {
			return nil, xerrors.Errorf("image scan error: %w", err)
		}
	}

	report, err = r.Filter(ctx, opt, report)
	if err != nil {
		return nil, xerrors.Errorf("filter error: %w", err)
	}

	return report.Results, nil
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

package scanner

import (
	"context"
	_ "embed"
	"fmt"
	"os"

	"path/filepath"
	"strings"

	"github.com/argonsecurity/go-environments/models"
	"github.com/pkg/errors"
	"github.com/samber/lo"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/oss"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/pipelines"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

const aquaPath = "/tmp/aqua"

//go:embed trivy-secret.yaml
var secretsConfig string

func Scan(ctx context.Context, opts flag.Options, cmdName, path string, envConfig *models.Configuration) (*trivyTypes.Report, []*buildsecurity.Pipeline, error) {
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
		return nil, nil, fmt.Errorf("init error: %w", err)
	}
	defer r.Close(ctx)

	repositoryPipelines := make([]*buildsecurity.Pipeline, 0)
	var report trivyTypes.Report
	var pipelinesScanResults trivyTypes.Results
	switch cmdName {
	case "image":
		opts.Target = path
		// Container image scanning
		if report, err = r.ScanImage(ctx, opts); err != nil {
			return nil, nil, fmt.Errorf("image scan error: %w", err)
		}
	default:
		if viper.GetString("triggered-by") == "PR" {
			if err = createDiffScanFs(envConfig); err != nil {
				return nil, nil, errors.Wrap(err, "failed create diff scan system")
			}
			opts.Target = aquaPath
		}

		if viper.GetBool("pipelines") {
			repositoryPipelines, pipelinesScanResults, err = pipelines.ExecutePipelineScanning(opts.Target)
			if err != nil {
				log.Logger.Errorf("failed execute pipeline scanning: %v", err)
			}
		}

		_ /* packageJsonFiles */, noLockFiles, filenameReplaceMap := oss.DetectPackageJsonFiles(opts.Target)

		if viper.GetBool("package-json") && len(noLockFiles) > 0 {
			log.Logger.Warn("package.json files without lock files found. Please run install before scanning or upload lock files")
			log.Logger.Warn("Generating lock files for package.json files")
			dir, newLocksToPackageJson, err := oss.GeneratePackageLockFiles(opts.Target, noLockFiles)
			if err != nil {
				log.Logger.Errorf("failed to generate package-lock.json: %s", err)
			} else {
				defer os.RemoveAll(dir)
			}
			filenameReplaceMap = lo.Assign(filenameReplaceMap, newLocksToPackageJson)
		}

		// Filesystem scanning
		if report, err = r.ScanFilesystem(ctx, opts); err != nil {
			return nil, nil, fmt.Errorf("image scan error: %w", err)
		}

		if filenameReplaceMap != nil {
			replaceFilenames(&report, filenameReplaceMap)
		}

	}

	report.Results = append(report.Results, pipelinesScanResults...)

	report, err = r.Filter(ctx, opts, report)
	if err != nil {
		return nil, nil, fmt.Errorf("filter error: %w", err)
	}

	if err = r.Report(opts, report); err != nil {
		return nil, nil, fmt.Errorf("report error: %w", err)
	}
	return &report, repositoryPipelines, nil
}

func replaceFilenames(report *trivyTypes.Report, fileMap map[string]string) {
	for i := range report.Results {
		result := &report.Results[i]
		if file, ok := fileMap[result.Target]; ok {
			result.Target = file
		}
	}
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

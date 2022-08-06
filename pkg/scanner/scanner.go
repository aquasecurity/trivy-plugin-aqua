package scanner

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"

	"path/filepath"
	"strings"

	"github.com/liamg/memoryfs"
	"github.com/pkg/errors"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/defsec/pkg/scan"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/pipelines"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"

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
	var pipelinesScanResults trivyTypes.Results
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
			pipelinesScanResults, err = ScanPipelines(ctx, repositoryPipelines, files, sourcesMap)
			fmt.Println(pipelinesScanResults)
			if err != nil {
				return nil, nil, errors.Wrap(err, "failed scan pipelines")
			}
		}

		// Filesystem scanning
		if report, err = r.ScanFilesystem(ctx, opt); err != nil {
			return nil, nil, xerrors.Errorf("image scan error: %w", err)
		}
	}

	report.Results = append(report.Results, pipelinesScanResults...)

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

func ScanPipelines(ctx context.Context, repositoryPipelines []*buildsecurity.Pipeline, files []types.File, sourcesMap map[string]ppConsts.Platform) (trivyTypes.Results, error) {
	memFs, err := CreateMemoryFs(files)
	if err != nil {
		return nil, errors.Wrap(err, "failed create memory fs")
	}
	pipelineScanner := pipelines.NewScanner()
	policyReaders, err := getPolicyReaders(policiesPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed get policy readers")
	}
	pipelineScanner.SetPolicyReaders(policyReaders)

	scanResults, err := pipelineScanner.ScanFS(context.WithValue(ctx, "sourcesMap", sourcesMap), memFs, "/")
	fmt.Println(scanResults)
	results := misconfsToResults(resultsToMisconf("pipeline", pipelineScanner.Name(), scanResults))
	return results, nil
}

func getPolicyReaders(policyDirPath string) ([]io.Reader, error) {
	var policyReaders []io.Reader

	filepath.WalkDir(policyDirPath, func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".rego") && !strings.HasSuffix(d.Name(), "_test.rego") {
			f, err := os.Open(filepath.ToSlash(path))
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed read policy %s", path))
			}
			policyReaders = append(policyReaders, f)
		}
		return nil
	})

	return policyReaders, nil
}

func resultsToMisconf(configType string, scannerName string, results scan.Results) []types.Misconfiguration {
	misconfs := map[string]types.Misconfiguration{}

	for _, result := range results {
		flattened := result.Flatten()

		query := fmt.Sprintf("data.%s.%s", result.RegoNamespace(), result.RegoRule())

		ruleID := result.Rule().LegacyID
		if ruleID == "" {
			ruleID = result.Rule().AVDID
		}

		cause := misconf.NewCauseWithCode(result)

		misconfResult := types.MisconfResult{
			Namespace: result.RegoNamespace(),
			Query:     query,
			Message:   flattened.Description,
			PolicyMetadata: types.PolicyMetadata{
				ID:                 ruleID,
				Type:               fmt.Sprintf("%s Security Check", scannerName),
				Title:              result.Rule().Summary,
				Description:        result.Rule().Explanation,
				Severity:           string(flattened.Severity),
				RecommendedActions: flattened.Resolution,
				References:         flattened.Links,
			},
			CauseMetadata: cause,
			Traces:        result.Traces(),
		}

		filePath := flattened.Location.Filename
		misconf, ok := misconfs[filePath]
		if !ok {
			misconf = types.Misconfiguration{
				FileType: configType,
				FilePath: filePath,
			}
		}

		if flattened.Warning {
			misconf.Warnings = append(misconf.Warnings, misconfResult)
		} else {
			switch flattened.Status {
			case scan.StatusPassed:
				misconf.Successes = append(misconf.Successes, misconfResult)
			case scan.StatusIgnored:
				misconf.Exceptions = append(misconf.Exceptions, misconfResult)
			case scan.StatusFailed:
				misconf.Failures = append(misconf.Failures, misconfResult)
			}
		}
		misconfs[filePath] = misconf
	}

	return types.ToMisconfigurations(misconfs)
}

func misconfsToResults(misconfs []types.Misconfiguration) trivyTypes.Results {
	// log.Logger.Infof("Detected config files: %d", len(misconfs))
	var results trivyTypes.Results
	for _, misconf := range misconfs {
		// log.Logger.Debugf("Scanned config file: %s", misconf.FilePath)

		var detected []trivyTypes.DetectedMisconfiguration

		for _, f := range misconf.Failures {
			detected = append(detected, toDetectedMisconfiguration(f, dbTypes.SeverityCritical, trivyTypes.StatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Warnings {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityMedium, trivyTypes.StatusFailure, misconf.Layer))
		}
		for _, w := range misconf.Successes {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, trivyTypes.StatusPassed, misconf.Layer))
		}
		for _, w := range misconf.Exceptions {
			detected = append(detected, toDetectedMisconfiguration(w, dbTypes.SeverityUnknown, trivyTypes.StatusException, misconf.Layer))
		}

		results = append(results, trivyTypes.Result{
			Target:            misconf.FilePath,
			Class:             trivyTypes.ClassConfig,
			Type:              misconf.FileType,
			Misconfigurations: detected,
		})
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Target < results[j].Target
	})

	return results
}

func toDetectedMisconfiguration(res types.MisconfResult, defaultSeverity dbTypes.Severity,
	status trivyTypes.MisconfStatus, layer types.Layer) trivyTypes.DetectedMisconfiguration {

	severity := defaultSeverity
	sev, err := dbTypes.NewSeverity(res.Severity)
	if err != nil {
		// log.Logger.Warnf("severity must be %s, but %s", dbTypes.SeverityNames, res.Severity)
	} else {
		severity = sev
	}

	msg := strings.TrimSpace(res.Message)
	if msg == "" {
		msg = "No issues found"
	}

	var primaryURL string

	// empty namespace implies a go rule from defsec, "builtin" refers to a built-in rego rule
	// this ensures we don't generate bad links for custom policies
	if res.Namespace == "" || strings.HasPrefix(res.Namespace, "builtin.") {
		primaryURL = fmt.Sprintf("https://avd.aquasec.com/misconfig/%s", strings.ToLower(res.ID))
		res.References = append(res.References, primaryURL)
	}

	return trivyTypes.DetectedMisconfiguration{
		ID:          res.ID,
		Type:        res.Type,
		Title:       res.Title,
		Description: res.Description,
		Message:     msg,
		Resolution:  res.RecommendedActions,
		Namespace:   res.Namespace,
		Query:       res.Query,
		Severity:    severity.String(),
		PrimaryURL:  primaryURL,
		References:  res.References,
		Status:      status,
		Layer:       layer,
		Traces:      res.Traces,
		CauseMetadata: types.CauseMetadata{
			Resource:  res.Resource,
			Provider:  res.Provider,
			Service:   res.Service,
			StartLine: res.StartLine,
			EndLine:   res.EndLine,
			Code:      res.Code,
		},
	}
}

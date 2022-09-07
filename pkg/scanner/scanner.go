package scanner

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"

	"github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	ppConsts "github.com/argonsecurity/pipeline-parser/pkg/consts"

	"path/filepath"
	"strings"

	"github.com/liamg/memoryfs"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/defsec/pkg/scan"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
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
			if err = createDiffScanFs(); err != nil {
				return nil, nil, errors.Wrap(err, "failed create diff scan system")
			}
			opts.Target = aquaPath
		}

		if viper.GetBool("pipelines") {
			var files []types.File
			repositoryPipelines, files, err = pipelines.GetPipelines(opts.Target)
			if err != nil {
				log.Logger.Errorf("failed to get pipelines: %v", err)
			}

			if len(repositoryPipelines) > 0 {
				pipelinesScanResults, err = ScanPipelines(ctx, repositoryPipelines, files)
				if err != nil {
					log.Logger.Errorf("failed scan pipelines: %s", err)
				}
			}
		}

		var (
			fileMap map[string]string = nil
			dir     string
		)

		if viper.GetBool("package-json") {
			dir, fileMap, err = oss.GeneratePackageLockFiles(opts.Target)
			if err != nil {
				log.Logger.Errorf("failed to generate package-lock.json: %s", err)
			} else {
				defer os.RemoveAll(dir)
			}
		}

		// Filesystem scanning
		if report, err = r.ScanFilesystem(ctx, opts); err != nil {
			return nil, nil, fmt.Errorf("image scan error: %w", err)
		}

		if fileMap != nil {
			fixPackageJsonPathes(&report, fileMap)
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

func fixPackageJsonPathes(report *trivyTypes.Report, fileMap map[string]string) {
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

// This function is copied from trivy.
func CreateMemoryFs(files []types.File) (*memoryfs.FS, map[string]ppConsts.Platform, error) {
	var sourcesMap = map[string]ppConsts.Platform{}
	memFs := memoryfs.New()

	for _, file := range files {
		if filepath.Dir(file.Path) != "." {
			if err := memFs.MkdirAll(filepath.Dir(file.Path), os.ModePerm); err != nil {
				return nil, nil, fmt.Errorf("memoryfs mkdir error: %w", err)
			}
		}
		if err := memFs.WriteFile(file.Path, file.Content, os.ModePerm); err != nil {
			return nil, nil, fmt.Errorf("memoryfs write error: %w", err)
		}
		sourcesMap[cleanse(file.Path)] = ppConsts.Platform(file.Type)
	}
	return memFs, sourcesMap, nil
}

func ScanPipelines(ctx context.Context, repositoryPipelines []*buildsecurity.Pipeline, files []types.File) (trivyTypes.Results, error) {
	memFs, sourcesMap, err := CreateMemoryFs(files)
	if err != nil {
		return nil, errors.Wrap(err, "failed create memory fs")
	}

	pipelineScanner := pipelines.NewScanner()
	policyReaders, err := getPolicyReaders()
	if err != nil {
		return nil, errors.Wrap(err, "failed get policy readers")
	}
	pipelineScanner.SetPolicyReaders(policyReaders)

	scanResults, err := pipelineScanner.ScanFS(context.WithValue(ctx, "sourcesMap", sourcesMap), memFs, ".")
	if err != nil {
		return nil, errors.Wrap(err, "failed scan pipelines")
	}
	results := misconfsToResults(resultsToMisconf("pipeline", pipelineScanner.Name(), scanResults))
	return results, nil
}

// Trivy uses policies that are embedded into a file in defsec.
// So in order to use our own policies we need to create a readers array that contains our policies,
// and leverage defsec's capability to inject them to the scanner.
func getPolicyReaders() ([]io.Reader, error) {
	var policyReaders []io.Reader

	if err := fs.WalkDir(pipelines.PipelineRules, ".", func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".rego") && !strings.HasSuffix(d.Name(), "_test.rego") {
			f, err := pipelines.PipelineRules.Open(path)
			if err != nil {
				return errors.Wrap(err, fmt.Sprintf("failed read policy %s", path))
			}
			policyReaders = append(policyReaders, f)
		}
		return nil
	}); err != nil {
		return nil, errors.Wrap(err, "failed read policies")
	}

	return policyReaders, nil
}

// This function is copied from trivy.
func resultsToMisconf(configType string, scannerName string, results scan.Results) []types.Misconfiguration {
	misconfs := map[string]types.Misconfiguration{}

	for _, result := range results {
		flattened := result.Flatten()

		query := fmt.Sprintf("data.%s.%s", result.RegoNamespace(), result.RegoRule())

		ruleID := result.Rule().AVDID
		if result.RegoNamespace() != "" && len(result.Rule().Aliases) > 0 {
			ruleID = result.Rule().Aliases[0]
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

// This function is copied from trivy.
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

// This function is copied from trivy.
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

// This function is copied from memoryfs
func cleanse(path string) string {
	var separator = string(filepath.Separator)
	path = strings.ReplaceAll(path, "/", separator)
	path = filepath.Clean(path)
	path = strings.TrimPrefix(path, ".")
	path = strings.TrimPrefix(path, separator)
	return path
}

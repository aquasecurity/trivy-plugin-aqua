package pipelines

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aquasecurity/defsec/pkg/scan"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/handler/misconf"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
	ppConsts "github.com/argonsecurity/pipeline-parser/pkg/consts"
	"github.com/liamg/memoryfs"
	"github.com/pkg/errors"
)

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

// Trivy uses policies that are embedded into a file in defsec.
// So in order to use our own policies we need to create a readers array that contains our policies,
// and leverage defsec's capability to inject them to the scanner.
func getPolicyReaders() ([]io.Reader, error) {
	var policyReaders []io.Reader

	if err := fs.WalkDir(PipelineRules, ".", func(path string, d fs.DirEntry, err error) error {
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".rego") && !strings.HasSuffix(d.Name(), "_test.rego") {
			f, err := PipelineRules.Open(path)
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
	path = strings.TrimPrefix(path, "."+separator)
	path = strings.TrimPrefix(path, separator)
	if path == "." {
		return ""
	}
	return path
}

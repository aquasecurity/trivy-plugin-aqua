package processor

import (
	"fmt"
	"strings"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/argonsecurity/go-environments"
	"github.com/argonsecurity/go-environments/models"

	"github.com/mitchellh/mapstructure"
	"github.com/pkg/errors"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/thoas/go-funk"
)

func fileInBase(target string, r types.Results) bool {
	for _, vBase := range r {
		if vBase.Target == target {
			return true
		}
	}
	return false
}

func PrDiffResults(r types.Results) (reports types.Results, err error) {
	for _, v := range r {
		// is head file and not exist in base
		inBase := false
		if strings.Contains(v.Target, "head") {
			toBase := strings.ReplaceAll(v.Target, "head", "base")
			inBase = fileInBase(toBase, r)
			// this is new file take full report
			if !inBase {
				reports = append(reports, v)
			} else {
				// in head and base
				for _, vBase := range r {
					if vBase.Target == toBase {
						// misconf
						diff, _ := funk.Difference(v.Misconfigurations, vBase.Misconfigurations)
						var misconf []types.DetectedMisconfiguration
						err = mapstructure.Decode(diff, &misconf)
						if err != nil {
							return reports, errors.Wrap(err, "failed decode misconf")
						}
						v.Misconfigurations = misconf
						// vulns
						diff, _ = funk.Difference(v.Vulnerabilities, vBase.Vulnerabilities)
						var vulns []types.DetectedVulnerability
						err = mapstructure.Decode(diff, &vulns)
						if err != nil {
							return reports, errors.Wrap(err, "failed decode vulns")
						}
						v.Vulnerabilities = vulns
						reports = append(reports, v)
					}
				}
			}
		}
	}

	// Cleanup tmp file names
	for k, v := range reports {
		if strings.Contains(v.Target, "head/") {
			v.Target = strings.Replace(v.Target, "head/", "", 1)
			reports[k] = v
		}
		if strings.Contains(v.Target, "base/") {
			v.Target = strings.Replace(v.Target, "base/", "", 1)
			reports[k] = v
		}
	}
	return reports, nil
}

// ProcessResults downloads the latest policies for the repository the process the results
// while evaluating them against the policies
func ProcessResults(reports types.Results,
	policies []*buildsecurity.Policy,
	checkSupIDMap map[string]string) (
	results []*buildsecurity.Result,
	_ map[string]*buildsecurity.PackageDependencies,
	avdUrlMap buildClient.ResultIdToUrlMap) {
	avdUrlMap = make(buildClient.ResultIdToUrlMap)

	dependencies := make(map[string]*buildsecurity.PackageDependencies)

	for _, rep := range reports {
		switch rep.Class {
		case types.ClassLangPkg, types.ClassOSPkg:
			targetPackageDependencies := getTargetPackageDependencies(rep)
			if len(targetPackageDependencies) > 0 {
				dependencies[rep.Target] = &buildsecurity.PackageDependencies{
					PackageDependencies: targetPackageDependencies,
				}
			}
			reportResults := addVulnerabilitiesResults(rep, policies, avdUrlMap)
			results = append(results, reportResults...)
		case types.ClassConfig:
			reportResults := addMisconfigurationResults(rep, policies, checkSupIDMap, avdUrlMap)
			results = append(results, reportResults...)
		case types.ClassSecret:
			reportResults := addSecretsResults(rep, policies)
			results = append(results, reportResults...)
		}
	}

	return results, dependencies, avdUrlMap
}

func EnhanceResults(results []*buildsecurity.Result, envConfig *models.Configuration) []*buildsecurity.Result {
	enhancedResults := make([]*buildsecurity.Result, len(results))
	log.Logger.Infof("source is %s", envConfig.Repository.Source)
	log.Logger.Infof("url is %s", envConfig.Repository.Url)
	log.Logger.Infof("branch is %s", envConfig.Branch)
	log.Logger.Infof("commit is %s", envConfig.CommitSha)

	for i, result := range results {

		result.FileLink = environments.GetFileLink(
			envConfig.Repository.Source,
			envConfig.Repository.Url,
			result.Filename,
			envConfig.Branch,
			envConfig.CommitSha,
		)

		log.Logger.Infof("file link is %s", result.FileLink)

		if result.StartLine != 0 {
			result.FileLineLink = environments.GetFileLineLink(
				envConfig.Repository.Source,
				envConfig.Repository.Url,
				result.Filename,
				envConfig.Branch,
				envConfig.CommitSha,
				int(result.StartLine),
				int(result.EndLine),
			)
		}
		enhancedResults[i] = result
	}
	return enhancedResults
}

func DistinguishPolicies(
	downloadedPolicies []*buildsecurity.Policy) (
	[]*buildsecurity.Policy,
	map[string]string) {

	var policies []*buildsecurity.Policy
	checkSupIDMap := make(map[string]string, len(downloadedPolicies))
	for _, policy := range downloadedPolicies {
		switch policy.PolicyType {
		case buildsecurity.PolicyTypeEnum_POLICY_TYPE_SUPPRESSION:
			for _, control := range policy.GetControls() {
				for _, avd := range control.AVDIDs {
					checkSupIDMap[avd] = policy.PolicyID
				}
			}
		case buildsecurity.PolicyTypeEnum_POLICY_TYPE_POLICY:
			policies = append(policies, policy)
		default:
			policies = append(policies, policy)
		}
	}
	return policies, checkSupIDMap
}

func addVulnerabilitiesResults(rep types.Result,
	downloadedPolicies []*buildsecurity.Policy,
	avdUrlMap buildClient.ResultIdToUrlMap) (
	results []*buildsecurity.Result) {
	for _, vuln := range rep.Vulnerabilities {

		var r buildsecurity.Result

		if customFields, ok := vuln.Custom.(map[string]interface{}); ok {
			if lineNumber, ok := customFields["lineNumber"].(int32); ok {
				r.StartLine = lineNumber
				r.EndLine = lineNumber
			}
		}

		r.PolicyResults = checkVulnAgainstPolicies(vuln, downloadedPolicies, rep.Target)
		r.Type = scanner.MatchResultType("VULNERABILITIES")
		r.Title = vuln.Title
		r.Message = vuln.Description
		r.Severity = scanner.MatchResultSeverity(vuln.Vulnerability.Severity)
		r.Filename = rep.Target
		r.AVDID = vuln.VulnerabilityID
		r.PkgName = vuln.PkgName
		r.InstalledVersion = vuln.InstalledVersion
		r.FixedVersion = vuln.FixedVersion
		r.DataSource = vuln.DataSource.Name
		if vuln.PublishedDate != nil {
			r.PublishedDate = vuln.PublishedDate.Unix()
		}
		if vuln.LastModifiedDate != nil {
			r.LastModified = vuln.LastModifiedDate.Unix()
		}

		avdUrlMap[buildClient.GenerateResultId(&r)] = vuln.PrimaryURL

		for vendor, cvssVal := range vuln.Vulnerability.CVSS {
			r.VendorScoring = append(r.VendorScoring, &buildsecurity.VendorScoring{
				V2Score:    float32(cvssVal.V2Score),
				V2Vector:   cvssVal.V2Vector,
				V3Score:    float32(cvssVal.V3Score),
				V3Vector:   cvssVal.V3Vector,
				VendorName: string(vendor),
				Severity:   int32(vuln.VendorSeverity[vendor]),
			})
		}

		results = append(results, &r)
	}

	return results
}

func getTargetPackageDependencies(rep types.Result) (dependencies []*buildsecurity.PackageDependency) {
	if rep.Class == types.ClassOSPkg {
		return dependencies
	}
	for _, pkg := range rep.Packages {
		var dependency buildsecurity.PackageDependency
		if pkg.ID == "" {
			dependency.ID = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)
		} else {
			dependency.ID = pkg.ID
		}
		dependency.Type = rep.Type
		dependency.ChildIDs = pkg.DependsOn
		dependencies = append(dependencies, &dependency)
	}

	return dependencies
}

func contains(slice []string, value string) bool {
	for _, s := range slice {
		if s == value {
			return true
		}
	}
	return false
}

func addSecretsResults(rep types.Result, downloadedPolicies []*buildsecurity.Policy) (results []*buildsecurity.Result) {
	for _, s := range rep.Secrets {
		var r buildsecurity.Result

		r.PolicyResults = checkSecretAgainstPolicies(s, downloadedPolicies, rep.Target)
		r.Type = scanner.MatchResultType("SECRETS")
		r.Title = s.Title
		r.Severity = scanner.MatchResultSeverity(s.Severity)
		r.Filename = rep.Target
		r.AVDID = s.RuleID
		r.StartLine = int32(s.StartLine)
		r.EndLine = int32(s.EndLine)
		r.Resource = string(s.Category)
		r.Message = s.Match

		results = append(results, &r)

	}
	return results
}

func checkVulnAgainstPolicies(
	vuln types.DetectedVulnerability,
	policies []*buildsecurity.Policy,
	filename string) (
	results []*buildsecurity.PolicyResult) {

	for _, policy := range policies {
		controls := policy.GetControls()
		var failed bool
		var reasons []string
		for _, control := range controls {
			if control.ScanType != buildsecurity.ScanTypeEnum_SCAN_TYPE_VULNERABILITY {
				continue
			}
			failed, reasons = checkAgainstSeverity(vuln.Severity, vuln.VulnerabilityID, control, failed, reasons, filename)
		}
		results = appendResults(results, policy, failed, reasons)
	}
	return results
}

func appendResults(results []*buildsecurity.PolicyResult,
	policy *buildsecurity.Policy,
	failed bool,
	reasons []string) []*buildsecurity.PolicyResult {
	results = append(results, &buildsecurity.PolicyResult{
		PolicyID: policy.PolicyID,
		Failed:   failed,
		Enforced: policy.Enforced,
		Reason:   strings.Join(reasons, "\n"),
	})
	return results
}

func checkSecretAgainstPolicies(
	secret ftypes.SecretFinding,
	policies []*buildsecurity.Policy,
	filename string) (
	results []*buildsecurity.PolicyResult) {

	location := fmt.Sprintf("%s#L%d-%d", filename, secret.StartLine, secret.EndLine)

	for _, policy := range policies {
		controls := policy.GetControls()
		var failed bool
		var reasons []string
		for _, control := range controls {
			if control.ScanType != buildsecurity.ScanTypeEnum_SCAN_TYPE_SECRET {
				continue
			}
			failed, reasons = checkAgainstSeverity(secret.Severity, secret.RuleID, control, failed, reasons, location)
		}
		results = appendResults(results, policy, failed, reasons)
	}
	return results
}

func addMisconfigurationResults(rep types.Result,
	downloadedPolicies []*buildsecurity.Policy,
	checkSupIDMap map[string]string,
	avdUrlMap buildClient.ResultIdToUrlMap) (results []*buildsecurity.Result) {
	for _, miscon := range rep.Misconfigurations {

		var r buildsecurity.Result
		resource := fmt.Sprintf("%s Resource", cases.Title(language.English).String(rep.Type))

		if miscon.CauseMetadata.Resource != "" {
			resource = miscon.CauseMetadata.Resource
		}

		policyId, suppressedId := checkSupIDMap[miscon.ID]

		if miscon.Status == types.StatusFailure {
			if suppressedId {
				log.Logger.Debugf("Skipping suppressed id: %s, due to Suppression ID: %s", miscon.ID, policyId)
				r.SuppressionID = policyId
			} else {
				r.PolicyResults = checkMisconfAgainstPolicies(miscon, downloadedPolicies, rep.Target)
			}
			r.AVDID = miscon.ID
			r.Title = miscon.Title
			r.Message = miscon.Message
			r.Resource = resource
			r.Severity = scanner.MatchResultSeverity(miscon.Severity)
			r.StartLine = int32(miscon.CauseMetadata.StartLine)
			r.EndLine = int32(miscon.CauseMetadata.EndLine)
			r.Filename = rep.Target
			r.Type = scanner.MatchResultType(rep.Type)

			avdUrlMap[buildClient.GenerateResultId(&r)] = miscon.PrimaryURL

			results = append(results, &r)
		}
	}
	return results
}

func checkMisconfAgainstPolicies(
	miscon types.DetectedMisconfiguration,
	policies []*buildsecurity.Policy,
	filename string) (
	results []*buildsecurity.PolicyResult) {

	location := fmt.Sprintf("%s#L%d-%d", filename, miscon.CauseMetadata.StartLine, miscon.CauseMetadata.EndLine)

	for _, policy := range policies {
		controls := policy.GetControls()
		var failed bool
		var reasons []string
		for _, control := range controls {

			if control.ScanType != buildsecurity.ScanTypeEnum_SCAN_TYPE_MISCONFIGURATION {
				continue
			}

			failed, reasons = checkAgainstSeverity(miscon.Severity, miscon.ID, control, failed, reasons, location)
			if len(control.AVDIDs) == 0 && (miscon.CauseMetadata.Provider != "" || miscon.CauseMetadata.Service != "") {

				if strings.EqualFold(control.Provider, miscon.CauseMetadata.Provider) &&
					control.Service == "" {
					failed = true
					reasons = append(
						reasons,
						fmt.Sprintf("[%s] Provider specific control breach %s [%s]", miscon.ID, control.Provider, location))
				}

				if strings.EqualFold(control.Provider, miscon.CauseMetadata.Provider) &&
					strings.EqualFold(control.Service, miscon.CauseMetadata.Service) {
					failed = true
					reasons = append(
						reasons,
						fmt.Sprintf("[%s] Service specific control breach %s:%s [%s]",
							miscon.ID,
							control.Provider,
							control.Service,
							location))
				}
			} else {
				for _, avdID := range control.AVDIDs {
					if avdID == miscon.ID {
						failed = true
						reasons = append(
							reasons,
							fmt.Sprintf("[%s] Specific ID control breach [%s]", miscon.ID, location))
					}
				}
			}

		}
		results = appendResults(results, policy, failed, reasons)

	}
	return results
}

func checkAgainstSeverity(severity string,
	id string,
	control *buildsecurity.PolicyControl,
	failed bool,
	reasons []string,
	location string) (
	bool, []string) {
	if scanner.MatchResultSeverity(severity) >= control.Severity &&
		control.Severity != buildsecurity.SeverityEnum_SEVERITY_UNKNOWN {
		failed = true
		reasons = append(reasons, fmt.Sprintf("[%s] Severity level control breach [%s]", id, location))
	}
	return failed, reasons
}

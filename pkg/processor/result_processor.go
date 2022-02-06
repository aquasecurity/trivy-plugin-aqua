package processor

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/buildClient"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

// ProcessResults downloads the latest policies for the repository the process the results
// while evaluating them against the policies
func ProcessResults(client buildClient.Client, reports report.Results) (results []*buildsecurity.Result) {
	downloadedPolicies, err := client.GetPoliciesForRepository()
	if err != nil {
		log.Logger.Errorf("Could not download the repository policies. %#v", err)
	}

	for _, rep := range reports {
		if rep.Class == report.ClassConfig {
			reportResults := addMisconfigurationResults(rep, downloadedPolicies)
			results = append(results, reportResults...)
		}
		if rep.Class == report.ClassLangPkg {
			reportResults := addVulnerabilitiesResults(rep)
			results = append(results, reportResults...)
		}
	}

	return results
}

func addVulnerabilitiesResults(rep report.Result) (results []*buildsecurity.Result) {
	for _, vuln := range rep.Vulnerabilities {

		var r buildsecurity.Result

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

		for vendor, cvssVal := range vuln.Vulnerability.CVSS {
			r.VendorScoring = append(r.VendorScoring, &buildsecurity.VendorScoring{
				V2Score:    float32(cvssVal.V2Score),
				V2Vector:   cvssVal.V2Vector,
				V3Score:    float32(cvssVal.V3Score),
				V3Vector:   cvssVal.V3Vector,
				VendorName: string(vendor),
			})
		}

		results = append(results, &r)
	}

	return results
}

func addMisconfigurationResults(rep report.Result, downloadedPolicies []*buildsecurity.Policy) (results []*buildsecurity.Result) {
	for _, miscon := range rep.Misconfigurations {

		var r buildsecurity.Result
		resource := fmt.Sprintf("%s Resource", strings.Title(rep.Type))
		if miscon.IacMetadata.Resource != "" {
			resource = miscon.IacMetadata.Resource
		}

		if miscon.Status == types.StatusFailure {
			r.PolicyResults = checkAgainstPolicies(miscon, downloadedPolicies, rep.Target)
			r.AVDID = miscon.ID
			r.Title = miscon.Title
			r.Message = miscon.Message
			r.Resource = resource
			r.Severity = scanner.MatchResultSeverity(miscon.Severity)
			r.StartLine = int32(miscon.IacMetadata.StartLine)
			r.EndLine = int32(miscon.IacMetadata.EndLine)
			r.Filename = rep.Target
			r.Type = scanner.MatchResultType(rep.Type)

			results = append(results, &r)
		}
	}
	return results
}

func checkAgainstPolicies(miscon types.DetectedMisconfiguration, policies []*buildsecurity.Policy, filename string) (
	results []*buildsecurity.PolicyResult) {

	location := fmt.Sprintf("%s#L%d-%d", filename, miscon.IacMetadata.StartLine, miscon.IacMetadata.EndLine)

	for _, policy := range policies {
		controls := policy.GetControls()
		var failed bool
		var reasons []string
		for _, control := range controls {

			if scanner.MatchResultSeverity(miscon.Severity) >= control.Severity && control.Severity != buildsecurity.SeverityEnum_SEVERITY_UNKNOWN {
				failed = true
				reasons = append(reasons, fmt.Sprintf("[%s] Severity level control breach [%s]", miscon.ID, location))
			}

			if len(control.AVDIDs) == 0 && (miscon.IacMetadata.Provider != "" || miscon.IacMetadata.Service != "") {
				if strings.ToLower(control.Provider) == strings.ToLower(miscon.IacMetadata.Provider) && control.Service == "" {
					failed = true
					reasons = append(reasons, fmt.Sprintf("[%s] Provider specific control breach %s [%s]", miscon.ID, control.Provider, location))
				}

				if strings.ToLower(control.Provider) == strings.ToLower(miscon.IacMetadata.Provider) &&
					strings.ToLower(control.Service) == strings.ToLower(miscon.IacMetadata.Service) {
					failed = true
					reasons = append(reasons, fmt.Sprintf("[%s] Service specific control breach %s:%s [%s]", miscon.ID, control.Provider, control.Service, location))
				}
			} else {
				for _, avdID := range control.AVDIDs {
					if avdID == miscon.ID {
						failed = true
						reasons = append(reasons, fmt.Sprintf("[%s] Specific ID control breach [%s]", miscon.ID, location))
					}
				}
			}

		}
		results = append(results, &buildsecurity.PolicyResult{
			PolicyID: policy.PolicyID,
			Failed:   failed,
			Enforced: policy.Enforced,
			Reason:   strings.Join(reasons, "\n"),
		})

	}
	return results
}

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
func ProcessResults(client buildClient.Client, report report.Results) (results []*buildsecurity.Result) {
	downloadedPolicies, err := client.GetPoliciesForRepository()
	if err != nil {
		log.Logger.Errorf("Could not download the repository policies. %#v", err)
	}

	for _, rep := range report {
		for _, miscon := range rep.Misconfigurations {

			var r buildsecurity.Result
			resource := fmt.Sprintf("%s Resource", strings.Title(rep.Type))
			if miscon.IacMetadata.Resource != "" {
				resource = miscon.IacMetadata.Resource
			}

			if miscon.Status == types.StatusFailure {
				r.PolicyResults = checkAgainstPolicies(miscon, downloadedPolicies)
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
	}
	return results
}

func checkAgainstPolicies(miscon types.DetectedMisconfiguration, policies []*buildsecurity.Policy) (
	results []*buildsecurity.PolicyResult) {
	for _, policy := range policies {
		controls := policy.GetControls()
		var failed bool
		var reason string
		for _, control := range controls {

			if scanner.MatchResultSeverity(miscon.Severity) >= control.Severity && control.Severity != buildsecurity.SeverityEnum_SEVERITY_UNKNOWN {
				failed = true
				reason = fmt.Sprintf("Identified issue with a severity of %s or higher", control.Severity)
				break
			}

			if miscon.IacMetadata.Provider != "" || miscon.IacMetadata.Service != "" {
				if strings.ToLower(control.Provider) == strings.ToLower(miscon.IacMetadata.Provider) && control.Service == "" {
					failed = true
					reason = fmt.Sprintf("Identified a provider specific issue %s:%s", control.Provider, miscon.ID)
					break
				}

				if strings.ToLower(control.Provider) == strings.ToLower(miscon.IacMetadata.Provider) &&
					strings.ToLower(control.Service) == strings.ToLower(miscon.IacMetadata.Service) {
					failed = true
					reason = fmt.Sprintf("Identified a service specific issue %s:%s:%s", control.Provider, control.Service, miscon.ID)
					break
				}
			}

			for _, avdID := range control.AVDIDs {
				if avdID == miscon.ID {
					failed = true
					reason = fmt.Sprintf("Identified issue %s", miscon.ID)
					break
				}
			}

		}
		results = append(results, &buildsecurity.PolicyResult{
			PolicyID: policy.PolicyID,
			Failed:   failed,
			Enforced: policy.Enforced,
			Reason:   reason,
		})

	}
	return results
}

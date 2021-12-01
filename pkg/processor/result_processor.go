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
func ProcessResults(client buildClient.Client, report report.Results) (results []*buildsecurity.Result, buildBreaker bool) {
	downloadedPolicies, err := client.GetPoliciesForRepository()
	if err != nil {
		log.Logger.Errorf("Could not download the repository policies. %w", err)
	}

	hasPolicies := len(downloadedPolicies) > 0

	for _, rep := range report {
		for _, miscon := range rep.Misconfigurations {

			if hasPolicies && hasPolicyMatch(miscon, downloadedPolicies) {
				buildBreaker = true
			}

			var r buildsecurity.Result
			resource := fmt.Sprintf("%s Resource", strings.Title(rep.Type))
			if miscon.IacMetadata.Resource != "" {
				resource = miscon.IacMetadata.Resource
			}

			if miscon.Status == "FAIL" {
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
	return results, buildBreaker
}

func hasPolicyMatch(miscon types.DetectedMisconfiguration, policies []*buildsecurity.Policy) bool {
	for _, policy := range policies {
		controls := policy.GetControls()
		for _, control := range controls {

			if control.Global {
				return true
			}

			if control.Provider == miscon.IacMetadata.Provider && control.Service == "" {
				return true
			}

			if control.Provider == miscon.IacMetadata.Provider && control.Service == miscon.IacMetadata.Service {
				return true
			}

			for _, avdiD := range control.AVDIDs {
				if avdiD == miscon.ID {
					return true
				}
			}
		}
	}
	return false
}

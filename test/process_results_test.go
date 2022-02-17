package test

import (
	"testing"
	"time"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/processor"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func Test_process_results_with_no_results(t *testing.T) {

	client := FakeClient{}
	policies, _ := client.GetPoliciesForRepository()

	results := processor.ProcessResults(nil, policies, nil)
	assert.Nil(t, results)

}

func Test_process_results_with_results_but_not_matching_policies(t *testing.T) {

	client := FakeClient{}

	results := report.Results{
		{
			Target: "main.tf",
			Class:  report.ClassConfig,
			Misconfigurations: []types.DetectedMisconfiguration{
				{
					Type:     "terraform",
					ID:       "AVD-AWS-0001",
					Severity: "MEDIUM",
					Status:   "FAIL",
					Layer:    ftypes.Layer{},
					IacMetadata: ftypes.IacMetadata{
						Resource: "aws_security_group_rule",
						Provider: "AWS",
						Service:  "vpc",
					},
				},
			},
		},
		{
			Target: "test.txt",
			Class:  report.ClassLangPkg,
			Vulnerabilities: []types.DetectedVulnerability{
				{
					DataSource:       &dbTypes.DataSource{Name: "test"},
					VulnerabilityID:  "123",
					PkgName:          `foo \ test`,
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:            `gcc: POWER9 "DARN" RNG intrinsic produces repeated output`,
						Description:      `curl version.`,
						Severity:         "HIGH",
						LastModifiedDate: &time.Time{},
						PublishedDate:    &time.Time{},
					},
				},
			},
		},
	}

	policies, _ := client.GetPoliciesForRepository()
	submitResults := processor.ProcessResults(results, policies, nil)

	assert.Len(t, submitResults, 2)
}

func Test_process_results_with_results_with_matching_policies_and_suppressions(t *testing.T) {

	client := FakeClient{}

	results := report.Results{
		{
			Target: "main.tf",
			Class:  report.ClassConfig,
			Misconfigurations: []types.DetectedMisconfiguration{
				{
					Type:     "terraform",
					ID:       "AVD-AWS-0001",
					Severity: "HIGH",
					Status:   "FAIL",
					Layer:    ftypes.Layer{},
					IacMetadata: ftypes.IacMetadata{
						Resource: "aws_s3_bucket",
						Provider: "AWS",
						Service:  "s3",
					},
				},
			},
		},

		{
			Target: "main.tf",
			Class:  report.ClassConfig,
			Misconfigurations: []types.DetectedMisconfiguration{
				{
					Type:     "terraform",
					ID:       "AVD-AWS-0002",
					Severity: "HIGH",
					Status:   "FAIL",
					Layer:    ftypes.Layer{},
					IacMetadata: ftypes.IacMetadata{
						Resource: "aws_s3_bucket",
						Provider: "AWS",
						Service:  "s3",
					},
				},
			},
		},
	}
	policies, _ := client.GetPoliciesForRepository()
	submitResults := processor.ProcessResults(results, policies, map[string]string{"AVD-AWS-0002": "policy-123"})

	assert.Len(t, submitResults, 2)
	SuppressionCount, policyCount := getSuppressionPolicyCount(submitResults)
	assert.Equal(t, SuppressionCount, 1)
	assert.Equal(t, policyCount, 1)
}

func getSuppressionPolicyCount(submitResults []*buildsecurity.Result) (int, int) {
	var SuppressionCount, policyCount int
	for _, res := range submitResults {
		if res.SuppressionID == "" {
			policyCount += 1
		} else {
			SuppressionCount += 1
		}
	}

	return SuppressionCount, policyCount
}

func Test_process_results_with_results_with_no_matching_policies_severity_level(t *testing.T) {

	client := FakeClient{}

	results := report.Results{
		{
			Target: "main.tf",
			Class:  report.ClassConfig,
			Misconfigurations: []types.DetectedMisconfiguration{
				{
					Type:     "terraform",
					ID:       "AVD-AWS-0001",
					Severity: "LOW",
					Status:   "FAIL",
					Layer:    ftypes.Layer{},
					IacMetadata: ftypes.IacMetadata{
						Resource: "aws_instance",
						Provider: "AWS",
						Service:  "ec2",
					},
				},
			},
		},
	}

	policies, _ := client.GetPoliciesForRepository()
	submitResults := processor.ProcessResults(results, policies, nil)

	assert.Len(t, submitResults, 1)
}

func Test_process_results_with_results_with_matching_policies_severity_level(t *testing.T) {

	client := FakeClient{}

	results := report.Results{
		{
			Target: "main.tf",
			Class:  report.ClassConfig,
			Misconfigurations: []types.DetectedMisconfiguration{
				{
					Type:     "terraform",
					ID:       "AVD-AWS-0001",
					Severity: "HIGH",
					Status:   "FAIL",
					Layer:    ftypes.Layer{},
					IacMetadata: ftypes.IacMetadata{
						Resource: "aws_instance",
						Provider: "AWS",
						Service:  "ec2",
					},
				},
			},
		},
	}
	policies, _ := client.GetPoliciesForRepository()

	submitResults := processor.ProcessResults(results, policies, nil)

	assert.Len(t, submitResults, 1)
}

func Test_process_results_with_results_with_matching_policies_severity_level_greater_than_specified(t *testing.T) {

	client := FakeClient{}

	results := report.Results{
		{
			Target: "main.tf",
			Class:  report.ClassConfig,
			Misconfigurations: []types.DetectedMisconfiguration{
				{
					Type:     "terraform",
					ID:       "AVD-AWS-0001",
					Severity: "CRITICAL",
					Status:   "FAIL",
					Layer:    ftypes.Layer{},
					IacMetadata: ftypes.IacMetadata{
						Resource: "aws_instance",
						Provider: "AWS",
						Service:  "ec2",
					},
				},
			},
		},
	}

	policies, _ := client.GetPoliciesForRepository()

	submitResults := processor.ProcessResults(results, policies, nil)

	assert.Len(t, submitResults, 1)
}

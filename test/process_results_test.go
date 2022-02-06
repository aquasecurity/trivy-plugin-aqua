package test

import (
	"testing"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/processor"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/stretchr/testify/assert"
)

func Test_process_results_with_no_results(t *testing.T) {

	client := FakeClient{}

	results := processor.ProcessResults(client, nil)
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
						Title:       `gcc: POWER9 "DARN" RNG intrinsic produces repeated output`,
						Description: `curl version curl \X 7.20.0 to and including curl 7.59.0 contains a CWE-126: Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded RTSP content.. This vulnerability appears to have been fixed in curl < 7.20.0 and curl >= 7.60.0.`,
						Severity:    "HIGH",
					},
				},
			},
		},
	}

	submitResults := processor.ProcessResults(client, results)

	assert.Len(t, submitResults, 2)
}

func Test_process_results_with_results_with_matching_policies(t *testing.T) {

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
	}

	submitResults := processor.ProcessResults(client, results)

	assert.Len(t, submitResults, 1)
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

	submitResults := processor.ProcessResults(client, results)

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

	submitResults := processor.ProcessResults(client, results)

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

	submitResults := processor.ProcessResults(client, results)

	assert.Len(t, submitResults, 1)
}

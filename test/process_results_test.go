package test

import (
	"testing"

	ftypes "github.com/aquasecurity/fanal/types"
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
	}

	submitResults := processor.ProcessResults(client, results)

	assert.Len(t, submitResults, 1)
}

func Test_process_results_with_results_with_matching_policies(t *testing.T) {

	client := FakeClient{}

	results := report.Results{
		{
			Target: "main.tf",
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

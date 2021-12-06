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

	results, policyFailures := processor.ProcessResults(client, nil)
	assert.Nil(t, results)
	assert.Nil(t, policyFailures)

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
					Severity: "HIGH",
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

	submitResults, policyFailures := processor.ProcessResults(client, results)

	assert.Len(t, submitResults, 1)
	assert.Nil(t, policyFailures)
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

	submitResults, policyFailures := processor.ProcessResults(client, results)

	assert.Len(t, submitResults, 1)
	assert.NotNil(t, policyFailures)
}

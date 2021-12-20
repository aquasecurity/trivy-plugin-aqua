package test

import "github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"

type FakeClient struct {
}

func (f FakeClient) Upload(results []*buildsecurity.Result, policyFailures []*buildsecurity.PolicyScanSummary, tags map[string]string) error {
	return nil
}

func (f FakeClient) GetPoliciesForRepository() ([]*buildsecurity.Policy, error) {

	return []*buildsecurity.Policy{
		{
			PolicyID: "f8de392c-55c3-4307-b2e8-18fae11257db",
			Controls: []*buildsecurity.PolicyControl{
				{
					Severity: buildsecurity.SeverityEnum_SEVERITY_HIGH,
					Provider: "AWS",
					Service:  "s3",
					AVDIDs:   nil,
				},
			},
		},
	}, nil

}

func (f FakeClient) GetOrCreateRepository() (string, error) {

	return "myRepo", nil
}

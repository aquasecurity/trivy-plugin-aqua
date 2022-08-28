package test

import "github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"

type FakeClient struct {
}

func (f FakeClient) Upload(results []*buildsecurity.Result, tags map[string]string, _ []*buildsecurity.Pipeline, _ map[string]*buildsecurity.PackageDependencies) error {
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
			PolicyType: buildsecurity.PolicyTypeEnum_POLICY_TYPE_POLICY,
		},
		{
			PolicyID: "f8de392c-55c3-4307-b2e8-18fae11257dc",
			Controls: []*buildsecurity.PolicyControl{
				{

					AVDIDs: []string{"AVD-123"},
				},
			},
			PolicyType: buildsecurity.PolicyTypeEnum_POLICY_TYPE_SUPPRESSION,
		},
	}, nil

}

func (f FakeClient) GetPolicyForRepositoryWithVulnControl() ([]*buildsecurity.Policy, error) {

	return []*buildsecurity.Policy{
		{
			PolicyID: "f8de392c-55c3-4307-b2e8-18fae11257db",
			Controls: []*buildsecurity.PolicyControl{
				{
					Severity: buildsecurity.SeverityEnum_SEVERITY_HIGH,
					ScanType: buildsecurity.ScanTypeEnum_SCAN_TYPE_VULNERABILITY,
				},
			},
			PolicyType: buildsecurity.PolicyTypeEnum_POLICY_TYPE_POLICY,
		},
	}, nil

}

func (f FakeClient) GetOrCreateRepository() (string, error) {

	return "myRepo", nil
}

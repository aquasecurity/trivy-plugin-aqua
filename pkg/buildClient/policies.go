package buildClient

import (
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

func (bc *TwirpClient) GetPoliciesForRepository() ([]*buildsecurity.Policy, error) {

	repoId, err := bc.GetOrCreateRepository()
	if err != nil {
		return nil, err
	}

	ctx, err := bc.createContext()
	if err != nil {
		return nil, err
	}

	log.Logger.Debugf("Getting policies for this repository")
	policyResponse, err := bc.client.GetPolicies(ctx, &buildsecurity.GetPoliciesReq{
		RepositoryID: repoId,
	})

	if err != nil {
		return nil, err
	}

	log.Logger.Debugf("Downloaded %d policies for this repository", len(policyResponse.Policies))

	return policyResponse.Policies, nil
}

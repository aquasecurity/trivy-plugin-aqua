package buildClient

import (
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

func (bc *TwirpClient) GetPoliciesForRepository() ([]*buildsecurity.Policy, error) {

	repoId, err := bc.UpsertRepository()
	if err != nil {
		return nil, err
	}

	ctx, err := bc.createContext()
	if err != nil {
		return nil, err
	}

	_, branch, err := metadata.GetRepositoryDetails(bc.scanPath, bc.cmdName)
	if err != nil {
		return nil, err
	}

	log.Logger.Debugf("Getting policies for repository %s", repoId)
	policyResponse, err := bc.client.GetPolicies(ctx, &buildsecurity.GetPoliciesReq{
		RepositoryID: repoId,
		Branch:       branch,
	})

	if err != nil {
		return nil, err
	}

	log.Logger.Debugf("Downloaded %d policies for this repository", len(policyResponse.Policies))

	return policyResponse.Policies, nil
}

package buildClient

import (
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

func (bc *TwirpClient) UpsertRepository() (string, error) {

	log.Logger.Debug("Getting the repository id for current scan path")
	if bc.repoId != "" {
		return bc.repoId, nil
	}

	ctx, err := bc.createContext()
	if err != nil {
		return "", err
	}

	scmID, err := bc.getScmID()
	if err != nil {
		return "", err
	}

	var repoId string
	repoName, err := bc.getRepoName()
	if err != nil {
		return "", err
	}

	topics, _ := getTopics(metadata.GetBuildSystem())

	newRepo, err := bc.client.UpsertRepository(ctx, &buildsecurity.UpsertRepositoryReq{
		SCMID:  scmID,
		Name:   repoName,
		Topics: topics,
	})

	if err != nil {
		return "", err
	}

	log.Logger.Debugf("Created new repository for %s", repoName)
	repoId = newRepo.RepositoryID

	bc.repoId = repoId
	return repoId, nil
}

func (bc *TwirpClient) getScmID() (scmID string, err error) {
	switch bc.cmdName {
	case "image":
		prefix, repo, _ := metadata.GetImageDetails(bc.scanPath)
		scmID = metadata.GetRepositoryUrl(prefix, repo)
	default:
		scmID = metadata.GetScmID(bc.scanPath)
	}

	return scmID, nil
}

func (bc *TwirpClient) getRepoName() (repoName string, err error) {
	switch bc.cmdName {
	case "image":
		prefix, repo, _ := metadata.GetImageDetails(bc.scanPath)
		repoName = metadata.GetRepositoryUrl(prefix, repo)
	default:
		repoName, _, err = metadata.GetRepositoryDetails(bc.scanPath, "")
		if err != nil {
			return "", err
		}
	}
	return repoName, nil
}

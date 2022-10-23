package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
	"github.com/argonsecurity/go-environments/enums"
	"github.com/argonsecurity/go-environments/models"
	"github.com/pkg/errors"
	"github.com/samber/lo"
)

type targetSubDir string

const (
	headPath targetSubDir = "head"
	basePath targetSubDir = "base"
)

const (
	gitStatusDeleted     = "D"
	gitStatusAdded       = "A"
	gitStatusRenamedOnly = "R100"
)

type DiffFile struct {
	Status     string
	Name       string
	DirName    string
	NewName    string
	NewDirName string
}

var relatedFilesMap map[string][]string = map[string][]string{
	"package.json": {"package-lock.json", "yarn.lock"},
}

func writeFile(path, content string) error {
	f, err := os.Create(path)
	if err != nil {
		return errors.Wrap(err, "failed create file")
	}
	defer f.Close()
	_, err = f.WriteString(content)
	if err != nil {
		f.Close()
		return errors.Wrap(err, "failed write file")
	}

	err = f.Close()
	if err != nil {
		return errors.Wrap(err, "failed close file")
	}
	return nil
}

// Create folders with head and base for diff scanning
func createDiffScanFs(envconfig *models.Configuration) error {
	// In GitHub we need fetch the remote branch first
	log.Logger.Infof("source is %s", envconfig.Repository.Source)
	if (envconfig.Repository.Source == enums.Github ||
		envconfig.Repository.Source == enums.GithubServer) &&
		strings.ToLower(envconfig.Builder) != string(enums.Jenkins) &&
		strings.ToLower(envconfig.Builder) != string(enums.CircleCi) {
		// In GitHub trivy action container we need safe directory to run git fetch
		log.Logger.Info("setting safe dir")
		_, err := git.GitExec("config", "--global", "--add", "safe.directory", "/github/workspace")
		if err != nil {
			return errors.Wrap(err, "failed git config adding safe.directory")
		}
		_, err = git.GitExec("fetch", "origin", fmt.Sprintf("refs/heads/%s", envconfig.PullRequest.TargetRef.Branch))
		if err != nil {
			return errors.Wrap(err, "failed git fetch ref")
		}
	}

	targetBranch := metadata.GetBaseRef(envconfig)
	diffFiles, err := getDiffFiles(targetBranch)
	if err != nil {
		return errors.Wrapf(err, "failed to create diff for PR scanning, envconfig: %+v", envconfig)
	}

	for _, v := range diffFiles {
		fileName := v.Name
		dirName := v.DirName
		if v.Status != gitStatusDeleted && v.Status != gitStatusRenamedOnly && v.Status != "" && fileName != "" {
			// Create base
			if v.Status != gitStatusAdded {
				err = fetchFile(targetBranch, fileName, v.DirName, basePath)
				if err != nil {
					return errors.Wrap(err, "failed write base file")
				}
			}
			if v.NewName != "" {
				fileName = v.NewName
				dirName = v.NewDirName
			}
			// Create head
			err := fetchFile("", fileName, dirName, headPath)
			if err != nil {
				return errors.Wrap(err, "failed write head file")
			}
		}
	}

	return nil
}

func getDiffFiles(targetBranch string) ([]DiffFile, error) {
	out, err := git.GitExec("diff", "--name-status", targetBranch)
	if err != nil {
		return nil, errors.Wrap(err, "failed git diff")
	}

	if out == "" {
		return nil, nil
	}

	return lo.FilterMap(strings.Split(out, "\n"), parseDiffFile), nil
}

func parseDiffFile(rawDiffFile string, _ int) (DiffFile, bool) {
	var diffFile DiffFile
	diffFileSplit := strings.Split(rawDiffFile, "\t")
	if len(diffFileSplit) < 2 {
		return diffFile, false
	}
	status := strings.TrimSpace(diffFileSplit[0])
	switch len(diffFileSplit) {
	case 2:
		name := strings.TrimSpace(diffFileSplit[1])
		diffFile = DiffFile{
			Status:  status,
			Name:    name,
			DirName: filepath.Dir(name),
		}
	case 3:
		name := strings.TrimSpace(diffFileSplit[1])
		newName := strings.TrimSpace(diffFileSplit[2])
		diffFile = DiffFile{
			Status:     status,
			Name:       name,
			DirName:    filepath.Dir(name),
			NewName:    newName,
			NewDirName: filepath.Dir(newName),
		}
	default:
		log.Logger.Debugf("Unknown git diff file format: %s", rawDiffFile)
		return diffFile, false
	}

	return diffFile, diffFile.Status != "" && diffFile.Name != ""
}

func fetchFile(baseRef, fileName, dirName string, target targetSubDir) error {
	err := os.MkdirAll(fmt.Sprintf("%s/%s/%s", aquaPath, target, dirName), os.ModePerm)
	if err != nil {
		return errors.Wrap(err, "failed mkdir aqua tmp path")
	}
	out, err := git.GitExec("show", fmt.Sprintf("%s:%s", baseRef, fileName))
	if err != nil {
		return errors.Wrapf(err, "failed git show %s:%s", baseRef, fileName)
	}
	err = writeFile(fmt.Sprintf("%s/%s/%s", aquaPath, target, fileName), out)
	if err != nil {
		return errors.Wrap(err, "failed write base file")
	}

	tryFetchRelatedFiles(baseRef, fileName, dirName, target)

	return nil
}

func tryFetchRelatedFiles(baseRef, fileName, dirName string, target targetSubDir) {
	relatedFiles, ok := relatedFilesMap[filepath.Base(fileName)]
	if !ok {
		return
	}
	for _, relatedFile := range relatedFiles {
		err := fetchFile(baseRef, filepath.Join(dirName, relatedFile), dirName, target)
		if err != nil {
			log.Logger.Debugf("Could not fetch related file %s:%s/%s, err: %w", baseRef, dirName, target, err)
		}
	}
}

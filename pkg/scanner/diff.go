package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/metadata"
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
func createDiffScanFs() error {
	// In GitHub we need fetch the remote branch first
	if os.Getenv("GITHUB_BASE_REF") != "" {
		// In GitHub trivy action container we need safe directory to run git fetch
		_, err := git.GitExec("config", "--global", "--add", "safe.directory", "/github/workspace")
		if err != nil {
			return errors.Wrap(err, "failed git fetch ref")
		}
		_, err = git.GitExec("fetch", "origin", fmt.Sprintf("refs/heads/%s", os.Getenv("GITHUB_BASE_REF")))
		if err != nil {
			return errors.Wrap(err, "failed git fetch ref")
		}
	}

	diffCmd := metadata.GetBaseRef()
	diffFiles, err := getDiffFiles(diffCmd)
	if err != nil {
		return errors.Wrap(err, "failed get diff files")
	}

	for _, v := range diffFiles {
		fileName := v.Name
		dirName := v.DirName
		if v.Status != gitStatusDeleted && v.Status != gitStatusRenamedOnly && v.Status != "" && fileName != "" {
			// Create base
			if v.Status != gitStatusAdded {
				err = fetchFile(diffCmd, fileName, v.DirName, basePath)
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

func getDiffFiles(diffCmd string) ([]DiffFile, error) {
	out, err := git.GitExec("diff", "--name-status", diffCmd)
	if err != nil {
		return nil, errors.Wrap(err, "failed git diff")
	}

	return parseDiffFiles(out), nil
}

func parseDiffFiles(warDiffFiles string) []DiffFile {
	return lo.FilterMap(strings.Split(warDiffFiles, "\n"), func(diffFile string, _ int) (DiffFile, bool) {
		parsedDiff := parseDiffFile(diffFile)
		return parsedDiff, parsedDiff.Status != "" && parsedDiff.Name != ""
	})
}

func parseDiffFile(rawDiffFile string) DiffFile {
	var diffFile DiffFile
	diffFileSplit := strings.Split(rawDiffFile, "\t")
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
	}

	return diffFile
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

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
	var fileName string

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
	out, err := git.GitExec("diff", "--name-status", diffCmd)
	if err != nil {
		return errors.Wrap(err, "failed git diff")
	}

	if out != "" {
		diffFiles := lo.Filter(strings.Split(out, "\n"), func(diffFile string, _ int) bool {
			return diffFile != ""
		})
		for _, v := range diffFiles {
			var status, name, newName, dirName string
			diffFile := strings.Split(v, "\t")
			status = strings.TrimSpace(diffFile[0])
			switch len(diffFile) {
			case 2:
				name = strings.TrimSpace(diffFile[1])
			case 3:
				name = strings.TrimSpace(diffFile[1])
				newName = strings.TrimSpace(diffFile[2])
			default:
				log.Logger.Debugf("Unknown git diff file format: %s", v)
				continue
			}

			dirName = filepath.Dir(name)
			fileName = name

			if status != gitStatusDeleted && status != gitStatusRenamedOnly && status != "" && fileName != "" {
				// Create base
				if status != gitStatusAdded {
					err = fetchFile(diffCmd, fileName, dirName, basePath)
					if err != nil {
						return errors.Wrap(err, "failed write base file")
					}
				}
				if newName != "" {
					dirName = filepath.Dir(newName)
					fileName = newName
				}
				// Create head
				err := fetchFile("", fileName, dirName, headPath)
				if err != nil {
					return errors.Wrap(err, "failed write head file")
				}
			}
		}
	}

	return nil
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

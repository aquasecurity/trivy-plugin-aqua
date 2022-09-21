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

const (
	gitStatusDeleted     = "D"
	gitStatusAdded       = "A"
	gitStatusRenamedOnly = "R100"
)

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
	var fileName string

	// In GitHub we need fetch the remote branch first
	if envconfig.Repository.Source == enums.Github {
		// In GitHub trivy action container we need safe directory to run git fetch
		_, err := git.GitExec("config", "--global", "--add", "safe.directory", "/github/workspace")
		if err != nil {
			return errors.Wrap(err, "failed git fetch ref")
		}
		_, err = git.GitExec("fetch", "origin", fmt.Sprintf("refs/heads/%s", envconfig.PullRequest.TargetRef.Branch))
		if err != nil {
			return errors.Wrap(err, "failed git fetch ref")
		}
	}

	targetBranch := metadata.GetBaseRef(envconfig)
	out, err := git.GitExec("diff", "--name-status", targetBranch)
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
					err = os.MkdirAll(fmt.Sprintf("%s/base/%s", aquaPath, dirName), os.ModePerm)
					if err != nil {
						return errors.Wrap(err, "failed mkdir aqua tmp path")
					}
					out, err = git.GitExec("show", fmt.Sprintf("%s:%s", targetBranch, fileName))
					if err != nil {
						return errors.Wrap(err, "failed git show origin:"+fileName)
					}
					err = writeFile(fmt.Sprintf("%s/base/%s", aquaPath, fileName), out)
					if err != nil {
						return errors.Wrap(err, "failed write base file")
					}
				}
				if newName != "" {
					dirName = filepath.Dir(newName)
					fileName = newName
				}
				// Create head
				err = os.MkdirAll(fmt.Sprintf("%s/head/%s", aquaPath, dirName), os.ModePerm)
				if err != nil {
					return errors.Wrap(err, "failed mkdir aqua tmp path")
				}

				out, err = git.GitExec("show", fmt.Sprintf(":%s", fileName))
				if err != nil {
					return errors.Wrap(err, "failed git show")
				}
				err = writeFile(fmt.Sprintf("%s/head/%s", aquaPath, fileName), out)
				if err != nil {
					return errors.Wrap(err, "failed write head file")
				}
			}
		}
	}

	return nil
}

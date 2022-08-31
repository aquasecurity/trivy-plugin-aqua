package oss

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
)

const packageJsonFileName = "package.json"
const packageLockFileName = "package-lock.json"
const yarnLockFileName = "yarn.lock"

func GeneratePackageLockFiles(path string) (string, map[string]string, error) {
	files := findPackageJsonFiles(path)

	var (
		err     error
		tmpDir  string
		fileDir string
	)

	tmpDir, err = os.MkdirTemp(path, "")

	if err != nil {
		return "", nil, err
	}

	packageLockToPackageJsonMap := make(map[string]string)

	for _, file := range files {
		bs, err := os.ReadFile(file)

		if err != nil {
			log.Logger.Warnf("Error occurred while reading file %s: %s", file, err.Error())

			continue
		}

		var packageJson PackageJson
		err = json.Unmarshal(bs, &packageJson)
		if err != nil {
			log.Logger.Warnf("Error occurred while unmarshalling file %s: %s", file, err.Error())

			continue
		}

		fileDir, err = os.MkdirTemp(tmpDir, "")
		if err != nil {
			log.Logger.Warnf("Error occurred while creating temp directory: %s", err.Error())

			continue
		}

		if lockpath, err := createPackageLockFile(fileDir, packageJson); err != nil {
			log.Logger.Warnf("Error occurred while creating package-lock.json file: %s", err.Error())
		} else {
			target, _ := filepath.Rel(path, file)
			source, _ := filepath.Rel(path, lockpath)
			packageLockToPackageJsonMap[source] = target
		}
	}

	return tmpDir, packageLockToPackageJsonMap, nil
}

func findPackageJsonFiles(dirPath string) []string {
	files := []string{}

	//nolint:errcheck
	filepath.Walk(dirPath, func(path string, f os.FileInfo, err error) error {
		f, err = os.Stat(path)

		if err != nil {
			log.Logger.Warnf("Error occurred while scanning path %s: %s", path, err)

			return nil
		}

		f_mode := f.Mode()

		if f.IsDir() && f.Name() == "node_modules" {
			return filepath.SkipDir
		}

		if f_mode.IsDir() || !f_mode.IsRegular() {
			return nil
		}

		if f.Name() == packageJsonFileName {
			packageLockPath := filepath.Join(filepath.Dir(path), packageLockFileName)
			if _, err := os.Stat(packageLockPath); !os.IsNotExist(err) {
				return nil
			}

			yarnLockPath := filepath.Join(filepath.Dir(path), yarnLockFileName)
			if _, err := os.Stat(yarnLockPath); !os.IsNotExist(err) {
				return nil
			}

			files = append(files, path)
		}

		return nil
	})

	return files
}

func createPackageJsonFile(dir string, packageJson PackageJson) error {
	filePath := filepath.Join(dir, packageJsonFileName)

	for key, version := range packageJson.Dependencies {
		if strings.HasPrefix(version, "link") {
			delete(packageJson.Dependencies, key)
		}
	}

	bs, err := json.Marshal(packageJson)
	if err != nil {
		return fmt.Errorf("Error occurred while marshalling file: %s", err.Error())
	}

	err = os.WriteFile(filePath, bs, 0600)
	if err != nil {
		return fmt.Errorf("Error occurred while writing file %s", err.Error())
	}

	return nil
}

func createPackageLockFile(dir string, packageJson PackageJson) (string, error) {
	packageRegexp := regexp.MustCompile(`https:\/\/registry\.npmjs\.org\/(.*) -`)

	shouldRetry := true

	for shouldRetry {
		if err := createPackageJsonFile(dir, packageJson); err != nil {
			return "", err
		}

		cmd := exec.Command(
			"npm",
			"install",
			"--package-lock-only",
			"--force",
		)

		cmd.Dir = dir
		var outb, errb bytes.Buffer
		cmd.Stdout = &outb
		cmd.Stderr = &errb
		shouldRetry = false
		if err := cmd.Run(); err != nil {
			errorStr := errb.String()
			matches := packageRegexp.FindStringSubmatch(errorStr)

			if len(matches) < 2 {
				return "", err
			} else {
				unfoundPackage, err := url.QueryUnescape(matches[1])

				if err != nil {
					return "", fmt.Errorf("Error occurred while unescaping package name %s: %s",
						matches[1], err.Error())
				}

				delete(packageJson.Dependencies, unfoundPackage)

				packagePrefixRegexp := regexp.MustCompile(`(@[^\/]*)\/.*`)

				matches = packagePrefixRegexp.FindStringSubmatch(unfoundPackage)

				if len(matches) > 1 {
					packagePrefix := matches[1]

					for key := range packageJson.Dependencies {
						if strings.HasPrefix(key, packagePrefix+"/") {
							delete(packageJson.Dependencies, key)
						}
					}
				}

				shouldRetry = true
			}
		}
	}
	return filepath.Join(dir, packageLockFileName), nil
}

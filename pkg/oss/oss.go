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
	"github.com/samber/lo"
)

var skipDirs = []string{"node_modules", ".git"}

const (
	packageJsonFileName = "package.json"
	packageLockFileName = "package-lock.json"
	yarnLockFileName    = "yarn.lock"
)

func GeneratePackageLockFiles(path string, noLockFiles map[string]PackageJson) (string, map[string]string, error) {
	var (
		err     error
		tmpDir  string
		fileDir string
	)

	tmpDir, err = os.MkdirTemp(path, "lockfiles-")

	if err != nil {
		return "", nil, err
	}

	newLockToPackageJsonMap := make(map[string]string)

	for filePath, file := range noLockFiles {
		tmpPattern := fmt.Sprintf("%s-*", strings.ReplaceAll(strings.TrimPrefix(filePath, path+"/"), "/", "-"))
		fileDir, err = os.MkdirTemp(tmpDir, tmpPattern)
		if err != nil {
			log.Logger.Warnf("Error occurred while creating temp directory: %s", err.Error())
			continue
		}

		if lockpath, err := createPackageLockFile(fileDir, file); err != nil {
			log.Logger.Warnf("Error occurred while creating package-lock.json file: %s", err.Error())
		} else {
			source, _ := filepath.Rel(path, lockpath)
			newLockToPackageJsonMap[source] = filePath
		}
	}

	return tmpDir, newLockToPackageJsonMap, nil
}

func DetectPackageJsonFiles(dirPath string) (map[string]PackageJson, map[string]PackageJson, map[string]string) {
	packageJsonFiles := make(map[string]PackageJson)
	noLockPackageJsonFiles := make(map[string]PackageJson)
	lockToPackageJson := map[string]string{}

	//nolint:errcheck
	filepath.Walk(dirPath, func(path string, f os.FileInfo, err error) error {
		f, err = os.Stat(path)

		if err != nil {
			log.Logger.Warnf("Error occurred while scanning path %s: %s", path, err)

			return nil
		}

		f_mode := f.Mode()

		if f.IsDir() && lo.Contains(skipDirs, f.Name()) {
			return filepath.SkipDir
		}

		if f_mode.IsDir() || !f_mode.IsRegular() {
			return nil
		}

		if f.Name() == packageJsonFileName {
			path = strings.TrimPrefix(path, dirPath+"/")

			packageJsonFiles[path] = readPackageJsonFile(path, dirPath)

			lockPath, foundPkgLock := findLockFile(path, dirPath, packageLockFileName)
			if foundPkgLock {
				lockToPackageJson[lockPath] = path
			}

			lockPath, foundYarnLock := findLockFile(path, dirPath, yarnLockFileName)
			if foundYarnLock {
				lockToPackageJson[lockPath] = path
			}

			if !foundPkgLock && !foundYarnLock {
				noLockPackageJsonFiles[path] = packageJsonFiles[path]
			}
		}
		return nil
	})

	return packageJsonFiles, noLockPackageJsonFiles, lockToPackageJson
}

func readPackageJsonFile(path, dirPath string) PackageJson {
	var packageJson PackageJson

	bs, err := os.ReadFile(filepath.Join(dirPath, path))
	if err != nil {
		log.Logger.Warnf("Error occurred while reading file %s: %s", path, err.Error())

		return packageJson
	}

	err = json.Unmarshal(bs, &packageJson)
	if err != nil {
		log.Logger.Warnf("Error occurred while unmarshalling file %s: %s", path, err.Error())

		return packageJson
	}

	return packageJson
}

func findLockFile(path, dirPath, lockFilename string) (string, bool) {
	lockPath := filepath.Join(filepath.Dir(path), lockFilename)
	if _, err := os.Stat(filepath.Join(dirPath, lockPath)); !os.IsNotExist(err) {
		return lockPath, true
	}
	return "", false
}

func createPackageJsonFile(dir string, packageJson PackageJson) error {
	filePath := filepath.Join(dir, packageJsonFileName)

	for key, dep := range packageJson.Dependencies {
		if strings.HasPrefix(dep.Version, "link") {
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

package metadata

import (
	"fmt"

	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
)

// GetScmID extracts the git path from the config file
func GetScmID(scanPath string) (string, error) {
	gitConfigFile := filepath.Join(scanPath, ".git", "config")
	gitConfig, err := ioutil.ReadFile(gitConfigFile)
	system := GetBuildSystem()
	if err == nil {
		re := regexp.MustCompile(`(?m)^\s*url\s?=\s*(.*)\s*$`)
		if re.Match(gitConfig) {
			scmID := re.FindStringSubmatch(string(gitConfig))[1]
			scmID = sanitiseScmId(system, scmID)

			return scmID, nil
		}
	}

	return filepath.Base(scanPath), nil
}

func sanitiseScmId(system string, scmID string) string {
	if system == "gitlab" {
		scmID = strings.Split(scmID, "@")[1]
	}
	return scmID
}

func GetBuildSystem() string {
	if v, ok := os.LookupEnv(overrideBuildSystem); ok {
		log.Logger.Debugf("Build system overridden, setting to %s", v)
		return v
	}

	for buildSystemEnv := range possibleBuildSystems {
		if _, ok := os.LookupEnv(buildSystemEnv); ok {
			return possibleBuildSystems[buildSystemEnv]
		}
	}

	log.Logger.Debug("Could not infer the build system from the env vars using 'other'")
	return "other"
}

// GetRepositoryDetails gets the repository name and branch
// multiple env vars will be checked first before falling back to the folder name
func GetRepositoryDetails(scanPath string) (repoName, branch string, err error) {

	for _, repoEnv := range possibleRepoEnvVars {
		if v, ok := os.LookupEnv(repoEnv); ok {
			repoName = v
			break
		}
	}

	for _, branchEnv := range possibleBranchEnvVars {
		if v, ok := os.LookupEnv(branchEnv); ok {
			branch = v
			break
		}
	}

	if repoName != "" && branch != "" {
		return repoName, branch, nil
	}

	workingDir := scanPath
	abs, err := filepath.Abs(workingDir)
	if err != nil {
		return "", "", err
	}

	inferredRepoName := filepath.Base(abs)
	repoRegex := regexp.MustCompile(`^(?i).+[:/](.+/.+)\.git`)
	scmID, err := GetScmID(scanPath)
	if err != nil {
		return inferredRepoName, "", err
	}
	if repoRegex.MatchString(scmID) {
		inferredRepoName = repoRegex.FindStringSubmatch(scmID)[1]
		log.Logger.Debugf("Extracted repo name from scmID: %s", inferredRepoName)
	}

	headFile := filepath.Join(workingDir, ".git", "HEAD")
	if _, err := os.Stat(headFile); err == nil {
		contents, err := ioutil.ReadFile(headFile)
		if err == nil {
			re := regexp.MustCompile("([^/]+$)")
			if re.Match(contents) {
				branch := strings.TrimSpace(re.FindString(string(contents)))
				log.Logger.Debugf("Extracted branch name from HEAD: %s", branch)
				return inferredRepoName, branch, nil
			}
		}
	}
	return inferredRepoName, "", nil
}

// GetCommitID gets the current CommitID of the repository
func GetCommitID(scanPath string) (commitId string) {

	for _, commitEnv := range possibleCommitIdsEnvVars {
		if v, ok := os.LookupEnv(commitEnv); ok {
			return v
		}
	}

	s, err := lastLogsHead(scanPath)
	if err == nil {
		if len(s) > 1 {
			return s[1]
		}
	}

	log.Logger.Debug("Could not infer the commit id")
	return "xxxxxxxxxxxxx"
}

// GetGitUser attempts to get the user who performed the most recent commit
func GetGitUser(scanPath string) (gitUser string) {

	for _, userEnv := range possibleUserEnvVars {
		if v, ok := os.LookupEnv(userEnv); ok {
			return v
		}
	}

	re := regexp.MustCompile(`(?m)^.*<(.+?)>`)
	logsHeadFile := filepath.Join(scanPath, ".git", "logs", "HEAD")
	if _, err := os.Stat(logsHeadFile); err == nil {
		contents, err := ioutil.ReadFile(logsHeadFile)
		if err == nil {
			matches := re.FindAllSubmatch(contents, -1)
			if len(matches) >= 1 {
				return string(matches[len(matches)-1][1])
			}
		}
	}

	if v, ok := os.LookupEnv("USERNAME"); ok {
		return fmt.Sprintf("Fallback: %s", v)
	}

	return "Unknown user"
}

func lastLogsHead(scanPath string) (s []string, err error) {
	logsHeadFile := filepath.Join(scanPath, ".git", "logs", "HEAD")
	if _, err := os.Stat(logsHeadFile); err == nil {
		contents, err := ioutil.ReadFile(logsHeadFile)
		if err != nil {
			return s, fmt.Errorf("failed to read %s err: %s", logsHeadFile, err)
		}
		logRaws := strings.Split(string(contents), "\n")
		if len(logRaws) > 2 {
			return strings.Split(logRaws[len(logRaws)-2], " "), nil
		}
		return strings.Split(logRaws[0], " "), nil

	}

	return s, nil
}

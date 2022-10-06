package metadata

import (
	"fmt"
	"net"

	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/git"
	"github.com/aquasecurity/trivy-plugin-aqua/pkg/log"
)

var (
	// SHARegexp is used to split an image digest value to a registry prefix,
	// repository name, and the SHA256 hash.
	SHARegexp = regexp.MustCompile(`^(?:([^/]+)/)([^@]+)(@sha256:[0-9a-f]+)$`)

	// SplitImageNameRegexp is used to split a fully qualified image name to a
	// registry prefix, repository name and image tag.
	SplitImageNameRegexp = regexp.MustCompile(`^(?:([^/]+)/)?([^:]+)(?::(.*))?$`)
	// PortRegexp is used to check whether a string ends with a port suffix
	// (e.g. :8080)
	PortRegexp = regexp.MustCompile(`:\d+$`)
)

func GetRepositoryUrl(prefix, repo string) string {
	if prefix != "" {
		return fmt.Sprintf("%s/%s", prefix, repo)
	}
	return repo
}

// GetImageDetails gets the full name of an image (e.g. "repo/test:master",
// or even "docker.io/repo/test:master") and splits it into the registry
// prefix, repository name and the image tag (e.g. "docker.io", "repo/test"
// and "master" in the previous example).
func GetImageDetails(imageName string) (prefix, repo, tag string) {
	if imageName == "" {
		return prefix, repo, tag
	}

	shaMatches := SHARegexp.FindStringSubmatch(imageName)
	if len(shaMatches) == 4 {
		prefix = shaMatches[1]
		repo = shaMatches[2]
		tag = shaMatches[3]
	} else {
		matches := SplitImageNameRegexp.FindStringSubmatch(imageName)
		if len(matches) < 3 {
			return prefix, repo, tag
		}

		prefix = matches[1]
		repo = matches[2]
		tag = matches[3]
	}

	// we may have extracted a prefix, but it may actually be part of the
	// repository name, because repository names can contain multiple slashes.
	// to verify, we will check that the prefix we extract is a valid IP address
	// or DNS name. We will also assume everything with a port suffix (e.g.
	// :8080) is a registry prefix
	if prefix != "" && !PortRegexp.MatchString(prefix) {
		if net.ParseIP(prefix) == nil {
			dns, _ := net.LookupIP(prefix)
			if len(dns) == 0 {
				// prefix is probably a part of the repository name
				if repo == "" {
					repo = prefix
				} else {
					repo = fmt.Sprintf("%s/%s", prefix, repo)
				}
				prefix = ""
			}
		}
	}

	return prefix, repo, tag
}

// GetScmID extracts the git path from the config file
func GetScmID(scanPath string) string {
	envScmId := os.Getenv(overrideScmId)
	if envScmId != "" {
		return envScmId
	}
	gitConfigFile := filepath.Join(scanPath, ".git", "config")
	gitConfig, err := os.ReadFile(gitConfigFile)
	if err == nil {
		re := regexp.MustCompile(`(?m)^\s*url\s?=\s*(.*)\s*$`)
		if re.Match(gitConfig) {
			scmID := re.FindStringSubmatch(string(gitConfig))[1]
			scmID = sanitizeScmId(scmID)

			return scmID
		}
	}

	return filepath.Base(scanPath)
}

// This function is the formula on the DB, on Atlas side and on Argon side,
// do not change without coordinating the change
func sanitizeScmId(scmID string) string {
	scmID = regexp.MustCompile("^.*@").ReplaceAllLiteralString(scmID, "")
	scmID = regexp.MustCompile("^https?://").ReplaceAllLiteralString(scmID, "")
	scmID = strings.TrimSuffix(scmID, ".git")
	scmID = strings.ReplaceAll(scmID, ":", "/")
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

// Get repository details based on FS scan
func getFsRepositoryDetails(scanPath string) (repoName, branch string, err error) {
	workingDir := scanPath
	abs, err := filepath.Abs(workingDir)
	if err != nil {
		return "", "", err
	}

	inferredRepoName := filepath.Base(abs)
	repoRegex := regexp.MustCompile(`^(?i).+[:/](.+/.+)`)
	scmID := GetScmID(scanPath)
	if repoRegex.MatchString(scmID) {
		inferredRepoName = repoRegex.FindStringSubmatch(scmID)[1]
		log.Logger.Debugf("Extracted repo name from scmID: %s", inferredRepoName)
	}

	out, giterr := git.GitExec("branch", "--show-current")
	if giterr != nil {
		log.Logger.Errorf("failed git branch --show-current: %w", err)
	}

	if out != "" {
		branches := strings.Split(out, "\n")
		if len(branches) > 0 {
			return inferredRepoName, branches[0], nil
		}
	}

	headFile := filepath.Join(workingDir, ".git", "HEAD")
	if _, err := os.Stat(headFile); err == nil {
		contents, err := os.ReadFile(headFile)
		if err == nil {
			arr := strings.Split(string(contents), "refs/heads/")
			if len(arr) > 1 {
				branch = strings.TrimSuffix(arr[1], "\n")
				log.Logger.Debugf("Extracted branch name from HEAD: %s", branch)
				return inferredRepoName, branch, nil
			}
		}
	}

	return inferredRepoName, "", nil
}

// GetRepositoryDetails gets the repository name and branch
// multiple env vars will be checked first before falling back to the folder name
func GetRepositoryDetails(scanPath string, cmd string) (repoName, branch string, err error) {

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

	switch cmd {
	case "image":
		prefix, repo, tag := GetImageDetails(scanPath)
		branch = tag
		repoName = GetRepositoryUrl(prefix, repo)
	default:
		repoName, branch, err = getFsRepositoryDetails(scanPath)
		if err != nil {
			return repoName, branch, fmt.Errorf("failed get FS repository details: %w", err)
		}
	}

	return repoName, branch, nil
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

func lastLogsHead(scanPath string) (s []string, err error) {
	logsHeadFile := filepath.Join(scanPath, ".git", "logs", "HEAD")
	if _, err := os.Stat(logsHeadFile); err == nil {
		contents, err := os.ReadFile(logsHeadFile)
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

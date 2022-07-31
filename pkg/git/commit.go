package git

import (
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

type Commit struct {
	SHA    string
	Date   string
	Author string
}

func GetFirstCommit(path string) (Commit, error) {
	dir := filepath.Dir(path)
	out, err := GitExecInDir(dir, "log", "--format=%H%x1f%ai%x1f%aN", "--diff-filter=A", "--", path)
	if err != nil {
		return Commit{}, errors.Wrap(err, "failed to get first commit")
	}

	var commit Commit
	if err := parseCommit(out, &commit); err != nil {
		return Commit{}, errors.Wrap(err, "failed to parse commit")
	}

	return commit, nil
}

// Gets the last commit that modified the file
func GetLastCommit(path string) (Commit, error) {
	dir := filepath.Dir(path)
	out, err := GitExecInDir(dir, "log", "-n", "1", "--format=%H%x1f%ai%x1f%aN", "--", path)
	if err != nil {
		return Commit{}, errors.Wrap(err, "failed to get last commit")
	}

	var commit Commit
	if err := parseCommit(out, &commit); err != nil {
		return Commit{}, errors.Wrap(err, "failed to parse commit")
	}

	return commit, nil
}

func parseCommit(out string, commit *Commit) error {
	lines := strings.Split(out, "\n")
	fields := strings.Split(lines[0], "\x1f")
	if len(fields) != 3 {
		return errors.New("invalid commit format")
	}

	commit.SHA = fields[0]
	commit.Date = fields[1]
	commit.Author = fields[2]

	return nil
}

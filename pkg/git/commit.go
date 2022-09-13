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

func (gc *Client) GetFirstCommit(path string) (Commit, error) {
	return gc.executeLogCommand(path, "log", "--format=%H%x1f%ai%x1f%aN", "--diff-filter=A", "--", path)
}

// Gets the last commit that modified the file
func (gc *Client) GetLastCommit(path string) (Commit, error) {
	return gc.executeLogCommand(path, "log", "-n", "1", "--format=%H%x1f%ai%x1f%aN", "--", path)
}

func (gc *Client) executeLogCommand(path string, args ...string) (Commit, error) {
	dir := filepath.Dir(path)
	out, err := gc.GitExecInDir(dir, args...)
	if err != nil {
		return Commit{}, errors.Wrap(err, "failed to get commit")
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

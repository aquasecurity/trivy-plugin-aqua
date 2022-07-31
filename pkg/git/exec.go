package git

import (
	"fmt"
	"os/exec"

	"github.com/pkg/errors"
)

type Commit struct {
	SHA    string
	Date   string
	Author string
}

func GitExec(args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed run git cmd output: %s", string(output)))
	}

	return string(output), nil
}

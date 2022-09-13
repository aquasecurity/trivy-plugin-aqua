package git

import (
	"fmt"
	"os/exec"

	"github.com/pkg/errors"
)

func (gc *Client) GitExec(args ...string) (string, error) {
	cmd := exec.Command(gc.binPath, args...) // #nosec G204
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed run git cmd output: %s", string(output)))
	}

	return string(output), nil
}

func (gc *Client) GitExecInDir(dir string, args ...string) (string, error) {
	cmd := exec.Command(gc.binPath, args...) // #nosec G204
	cmd.Dir = dir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", errors.Wrap(err, fmt.Sprintf("failed run git cmd output: %s", string(output)))
	}
	return string(output), nil
}

package git

import "os/exec"

type GitClient interface {
	GetFirstCommit(path string) (Commit, error)
	GetLastCommit(path string) (Commit, error)
	GitExec(args ...string) (string, error)
	GitExecInDir(dir string, args ...string) (string, error)
}

type Client struct {
	binPath string
}

func InitClient(gitPath string) (*Client, error) {
	var err error
	if gitPath == "" {
		gitPath, err = exec.LookPath("git")
		if err != nil {
			return nil, err
		}
	}

	return &Client{
		binPath: gitPath,
	}, nil
}

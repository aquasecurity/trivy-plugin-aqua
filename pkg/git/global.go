package git

var (
	GlobalGitClient GitClient
)

func init() {
	var err error
	GlobalGitClient, err = InitClient("")
	if err != nil {
		panic(err)
	}
}

func GetFirstCommit(path string) (Commit, error) {
	return GlobalGitClient.GetFirstCommit(path)
}

func GetLastCommit(path string) (Commit, error) {
	return GlobalGitClient.GetLastCommit(path)
}

func GitExec(args ...string) (string, error) {
	return GlobalGitClient.GitExec(args...)
}

func GitExecInDir(dir string, args ...string) (string, error) {
	return GlobalGitClient.GitExecInDir(dir, args...)
}

package mocks

import "github.com/aquasecurity/trivy-plugin-aqua/pkg/git"

type MockGitClient struct {
	firstCommit git.Commit
	lastCommit  git.Commit

	commandResult string

	err error
}

// Setters
func (m *MockGitClient) SetFirstCommit(commit git.Commit) *MockGitClient {
	m.firstCommit = commit
	return m
}

func (m *MockGitClient) SetLastCommit(commit git.Commit) *MockGitClient {
	m.lastCommit = commit
	return m
}

func (m *MockGitClient) SetError(err error) *MockGitClient {
	m.err = err
	return m
}

func (m *MockGitClient) SetCommandResult(result string) *MockGitClient {
	m.commandResult = result
	return m
}

// Implementations
func (m *MockGitClient) GetFirstCommit(path string) (git.Commit, error) {
	return m.firstCommit, m.err
}

func (m *MockGitClient) GetLastCommit(path string) (git.Commit, error) {
	return m.lastCommit, m.err
}

func (m *MockGitClient) GitExec(args ...string) (string, error) {
	return m.commandResult, m.err
}

func (m *MockGitClient) GitExecInDir(dir string, args ...string) (string, error) {
	return m.commandResult, m.err
}

// Set the global git client to the mock
func SetGitMock(mock *MockGitClient) {
	git.GlobalGitClient = mock
}

// Make sure MockGitClient implements GitClient
var _ git.GitClient = &MockGitClient{}

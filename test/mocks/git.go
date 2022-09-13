package mocks

import "github.com/aquasecurity/trivy-plugin-aqua/pkg/git"

type MockGitClient struct {
	firstCommit git.Commit
	lastCommit  git.Commit

	commandResult string
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

func (m *MockGitClient) SetCommandResult(result string) *MockGitClient {
	m.commandResult = result
	return m
}

// Implementations
func (m *MockGitClient) GetFirstCommit(path string) (git.Commit, error) {
	return m.firstCommit, nil
}

func (m *MockGitClient) GetLastCommit(path string) (git.Commit, error) {
	return m.lastCommit, nil
}

func (m *MockGitClient) GitExec(args ...string) (string, error) {
	return m.commandResult, nil
}

func (m *MockGitClient) GitExecInDir(dir string, args ...string) (string, error) {
	return m.commandResult, nil
}

// Set the global git client to the mock
func SetGitMock(mock *MockGitClient) {
	git.GlobalGitClient = mock
}

// Make sure MockGitClient implements GitClient
var _ git.GitClient = &MockGitClient{}

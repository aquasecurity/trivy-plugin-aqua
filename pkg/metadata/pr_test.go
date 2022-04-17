package metadata

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetGitDiffCmd(t *testing.T) {
	os.Setenv("BUILD_SOURCEBRANCH", "commit")
	os.Setenv("SYSTEM_PULLREQUEST_TARGETBRANCH", "refs/heads/master")
	r := GetGitDiffCmd()
	assert.Equal(t, "base/master", r)
}

package metadata

import (
	"testing"
)

func Test_convertScmId(t *testing.T) {
	type args struct {
		system string
		scmID  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "happy path - bitbucket",
			args: args{
				scmID:  "git@bitbucket.org:repo.git",
				system: "bitbucket",
			},
			want: "git@bitbucket.org:repo.git",
		},
		{
			name: "happy path - github",
			args: args{
				scmID:  "https://github.com/repo.git",
				system: "github",
			},
			want: "https://github.com/repo.git",
		},
		{
			name: "happy path - other",
			args: args{
				scmID:  "git@othertest.com/repo.git",
				system: "other",
			},
			want: "git@othertest.com/repo.git",
		},

		{
			name: "happy path - gitlab",
			args: args{
				scmID:  "https://gitlab-ci-token:123456-abcdef@gitlab.com/aqua/repo.git",
				system: "gitlab",
			},
			want: "gitlab.com/aqua/repo.git",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sanitiseScmId(tt.args.system, tt.args.scmID); got != tt.want {
				t.Errorf("sanitiseScmId() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRepositoryUrl(t *testing.T) {
	type args struct {
		prefix string
		repo   string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "happy path",
			args: args{prefix: "prefix", repo: "repo"},
			want: "prefix/repo",
		},
		{
			name: "happy path - only repo",
			args: args{repo: "repo"},
			want: "repo",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetRepositoryUrl(tt.args.prefix, tt.args.repo); got != tt.want {
				t.Errorf("GetRepositoryUrl() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetImageDetails(t *testing.T) {
	type args struct {
		imageName string
	}
	tests := []struct {
		name       string
		args       args
		wantPrefix string
		wantRepo   string
		wantTag    string
	}{
		{
			name:       "happy path - full docker url",
			args:       args{imageName: "docker.io/repo/test:master"},
			wantPrefix: "docker.io",
			wantRepo:   "repo/test",
			wantTag:    "master",
		},
		{
			name:       "happy path - docker url",
			args:       args{imageName: "repo/test:master"},
			wantPrefix: "",
			wantRepo:   "repo/test",
			wantTag:    "master",
		},
		{
			name:       "happy path - docker full url two /",
			args:       args{imageName: "docker.io/library/centos:latest"},
			wantPrefix: "docker.io",
			wantRepo:   "library/centos",
			wantTag:    "latest",
		},
		{
			name:       "happy path - docker url two",
			args:       args{imageName: "library/centos:latest"},
			wantPrefix: "",
			wantRepo:   "library/centos",
			wantTag:    "latest",
		},
		{
			name:       "happy path - aws ecr",
			args:       args{imageName: "1111111.dkr.ecr.us-east-1.amazonaws.com/alpine:3.9.4"},
			wantPrefix: "1111111.dkr.ecr.us-east-1.amazonaws.com",
			wantRepo:   "alpine",
			wantTag:    "3.9.4",
		},
		{
			name: "happy path - docker hash",
			args: args{
				imageName: "docker.io/repo/test@sha256:715760eedeabb0ca7b5758d4536e78c4c06cad699caa912bf1ef0f483b103efc",
			},
			wantPrefix: "docker.io",
			wantRepo:   "repo/test",
			wantTag:    "@sha256:715760eedeabb0ca7b5758d4536e78c4c06cad699caa912bf1ef0f483b103efc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPrefix, gotRepo, gotTag := GetImageDetails(tt.args.imageName)
			if gotPrefix != tt.wantPrefix {
				t.Errorf("GetImageDetails() gotPrefix = %v, want %v", gotPrefix, tt.wantPrefix)
			}
			if gotRepo != tt.wantRepo {
				t.Errorf("GetImageDetails() gotRepo = %v, want %v", gotRepo, tt.wantRepo)
			}
			if gotTag != tt.wantTag {
				t.Errorf("GetImageDetails() gotTag = %v, want %v", gotTag, tt.wantTag)
			}
		})
	}
}

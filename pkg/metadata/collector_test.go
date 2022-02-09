package metadata

import "testing"

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

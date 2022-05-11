package scanner

import (
	"testing"

	types "github.com/aquasecurity/trivy/pkg/types"
)

func Test_hasSecurityCheck(t *testing.T) {
	type args struct {
		slice []types.SecurityCheck
		value types.SecurityCheck
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "happy path - contains",
			args: args{
				slice: []types.SecurityCheck{
					types.SecurityCheckVulnerability,
					types.SecurityCheckSecret,
					types.SecurityCheckConfig,
				},
				value: types.SecurityCheckSecret,
			},
			want: true,
		},

		{
			name: "happy path - does not contain",
			args: args{
				slice: []types.SecurityCheck{types.SecurityCheckVulnerability, types.SecurityCheckConfig},
				value: types.SecurityCheckSecret,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := hasSecurityCheck(tt.args.slice, tt.args.value); got != tt.want {
				t.Errorf("hasSecurityCheck() = %v, want %v", got, tt.want)
			}
		})
	}
}

package processor

import (
	"reflect"
	"testing"

	"github.com/aquasecurity/trivy-plugin-aqua/pkg/proto/buildsecurity"
)

func Test_contains(t *testing.T) {
	type args struct {
		slice []string
		value string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "happy path - contains",
			args: args{
				slice: []string{"a", "b", "c"},
				value: "b",
			},
			want: true,
		},

		{
			name: "happy path - does not contain",
			args: args{
				slice: []string{"a", "b", "c"},
				value: "d",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := contains(tt.args.slice, tt.args.value); got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_distinguishPolicies(t *testing.T) {
	type args struct {
		downloadedPolicies []*buildsecurity.Policy
	}
	tests := []struct {
		name              string
		args              args
		wantPolicies      []*buildsecurity.Policy
		wantSuppressedIds map[string]string
	}{
		{
			name: "happy path - separate policies and suppressed ids",
			args: args{downloadedPolicies: []*buildsecurity.Policy{
				{
					PolicyType: buildsecurity.PolicyTypeEnum_POLICY_TYPE_SUPPRESSION,
					PolicyID:   "id1",
					Controls: []*buildsecurity.PolicyControl{
						{
							AVDIDs: []string{"123"},
						},
					},
				},
				{
					PolicyType: buildsecurity.PolicyTypeEnum_POLICY_TYPE_SUPPRESSION,
					PolicyID:   "id2",
					Controls: []*buildsecurity.PolicyControl{
						{
							AVDIDs: []string{"456"},
						},
					},
				},
				{
					PolicyType: buildsecurity.PolicyTypeEnum_POLICY_TYPE_POLICY,
					Controls: []*buildsecurity.PolicyControl{
						{
							AVDIDs: []string{"789"},
						},
					},
				},
			}},
			wantPolicies: []*buildsecurity.Policy{
				{
					PolicyType: buildsecurity.PolicyTypeEnum_POLICY_TYPE_POLICY,
					Controls: []*buildsecurity.PolicyControl{
						{
							AVDIDs: []string{"789"},
						},
					},
				},
			},
			wantSuppressedIds: map[string]string{"123": "id1", "456": "id2"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotPolicies, gotSuppressedIds := DistinguishPolicies(tt.args.downloadedPolicies)
			if !reflect.DeepEqual(gotPolicies, tt.wantPolicies) {
				t.Errorf("distinguishPolicies() gotPolicies = %v, want %v", gotPolicies, tt.wantPolicies)
			}
			if !reflect.DeepEqual(gotSuppressedIds, tt.wantSuppressedIds) {
				t.Errorf("distinguishPolicies() gotSuppressedIds = %v, want %v", gotSuppressedIds, tt.wantSuppressedIds)
			}
		})
	}
}

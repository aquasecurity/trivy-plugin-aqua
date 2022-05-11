package main

import (
	"reflect"
	"testing"
)

func Test_convertToTags(t *testing.T) {
	type args struct {
		t []string
	}
	tests := []struct {
		name     string
		args     args
		wantTags map[string]string
	}{
		{
			name:     "happy path - tag",
			args:     args{[]string{"key:val"}},
			wantTags: map[string]string{"key": "val"},
		},
		{
			name:     "happy path - tags",
			args:     args{[]string{"key0:val0", "key1:val1"}},
			wantTags: map[string]string{"key0": "val0", "key1": "val1"},
		},
		{
			name:     "happy path - invalid value",
			args:     args{[]string{"key0:"}},
			wantTags: map[string]string{},
		},
		{
			name:     "happy path - invalid tag",
			args:     args{[]string{"key0"}},
			wantTags: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotTags := convertToTags(tt.args.t); !reflect.DeepEqual(gotTags, tt.wantTags) {
				t.Errorf("convertToTags() = %v, want %v", gotTags, tt.wantTags)
			}
		})
	}
}

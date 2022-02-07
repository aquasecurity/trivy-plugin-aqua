package processor

import "testing"

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
		t.Run(tt.name, func(t *testing.T) {
			if got := contains(tt.args.slice, tt.args.value); got != tt.want {
				t.Errorf("contains() = %v, want %v", got, tt.want)
			}
		})
	}
}

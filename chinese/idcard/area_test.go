package idcard

import (
	"testing"
)

func TestRegisterCode(t *testing.T) {
	type args struct {
		data map[string]string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			RegisterCode(tt.args.data)
		})
	}
}

func TestConcatCode(t *testing.T) {
	type args struct {
		data map[string]string
	}
	tests := []struct {
		name string
		args args
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ConcatCode(tt.args.data)
		})
	}
}

package main

import (
	"reflect"
	"testing"
)

func TestHelpToArgv(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"bare help", []string{"help"}, []string{"aws", "help"}},
		{"help topic", []string{"help", "s3"}, []string{"aws", "help", "s3"}},
		{"aws passthrough", []string{"aws", "s3", "ls"}, []string{"aws", "s3", "ls"}},
		{"other command untouched", []string{"id"}, []string{"id"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := helpToArgv(tc.in); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("helpToArgv(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}


func TestAccountFromArn(t *testing.T) {
	cases := []struct {
		name, arn, want string
	}{
		{"assumed role", "arn:aws:sts::123456789012:assumed-role/tier-dbbackup/dbbackup", "123456789012"},
		{"role path", "arn:aws:sts::999888777666:assumed-role/path/tier-x/session", "999888777666"},
		{"not an arn", "something-else", ""},
		{"short arn", "arn:aws:sts", ""},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := accountFromArn(tc.arn); got != tc.want {
				t.Fatalf("accountFromArn(%q) = %q, want %q", tc.arn, got, tc.want)
			}
		})
	}
}

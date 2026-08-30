package main

import (
	"reflect"
	"testing"
)

func TestUseraddArgs(t *testing.T) {
	got := useraddArgs("dbbackup")
	want := []string{"-m", "-G", "awsjail", "-s", "/usr/local/bin/awsjail", "dbbackup"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("useraddArgs = %v, want %v", got, want)
	}
}

func TestUsermodArgs(t *testing.T) {
	got := usermodArgs("dbbackup")
	want := []string{"-s", "/usr/local/bin/awsjail", "-aG", "awsjail", "dbbackup"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("usermodArgs = %v, want %v", got, want)
	}
}

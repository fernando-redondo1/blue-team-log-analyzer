package parser

import (
	"path/filepath"
	"testing"
)

func TestParseApacheLog(t *testing.T) {
	logPath := filepath.Join("..", "..", "testdata", "sample-apache.log")
	events, err := ParseApacheLog(logPath)
	if err != nil {
		t.Fatalf("ParseApacheLog returned error: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected parsed Apache events, got none")
	}
}

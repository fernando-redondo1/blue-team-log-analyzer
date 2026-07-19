package parser

import (
	"path/filepath"
	"testing"
)

func TestParseSSHLog(t *testing.T) {
	logPath := filepath.Join("..", "..", "testdata", "sample-auth.log")
	events, err := ParseSSHLog(logPath)
	if err != nil {
		t.Fatalf("ParseSSHLog returned error: %v", err)
	}

	if len(events) == 0 {
		t.Fatal("expected parsed events, got none")
	}

	if events[0].Action == "" {
		t.Fatal("expected parsed event action to be present")
	}
}

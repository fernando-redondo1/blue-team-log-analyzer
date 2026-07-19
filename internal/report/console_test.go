package report

import (
	"bytes"
	"io"
	"os"
	"testing"

	"log-anomaly-detector/internal/detection"
)

func TestPrintAlertsIncludesSeverityAndReason(t *testing.T) {
	var buf bytes.Buffer
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe failed: %v", err)
	}
	os.Stdout = writer
	defer func() { os.Stdout = original }()

	PrintAlerts([]detection.Alert{{SourceIP: "1.2.3.4", Score: 0.9, Reason: "test reason", Severity: "high"}})

	writer.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read pipe failed: %v", err)
	}

	output := buf.String() + string(data)
	if !contains(output, "1.2.3.4") || !contains(output, "high") || !contains(output, "test reason") {
		t.Fatalf("expected rich alert output, got %q", output)
	}
}

func contains(s, sub string) bool {
	return bytes.Contains([]byte(s), []byte(sub))
}

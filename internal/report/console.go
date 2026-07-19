package report

import (
	"fmt"

	"log-anomaly-detector/internal/detection"
)

// PrintAlerts prints alerts to stdout.
func PrintAlerts(alerts []detection.Alert) {
	if len(alerts) == 0 {
		fmt.Println("No suspicious activity detected.")
		return
	}
	fmt.Println("Suspicious activity detected:")
	for _, alert := range alerts {
		fmt.Printf("- IP: %s | severity: %s | score: %.2f | reason: %s\n", alert.SourceIP, alert.Severity, alert.Score, alert.Reason)
	}
}

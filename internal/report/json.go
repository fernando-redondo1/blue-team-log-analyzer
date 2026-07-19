package report

import (
	"encoding/json"
	"fmt"
	"os"

	"log-anomaly-detector/internal/detection"
)

// WriteJSON writes alerts as JSON to stdout or a file if requested.
func WriteJSON(alerts []detection.Alert, path string) error {
	data, err := json.MarshalIndent(alerts, "", "  ")
	if err != nil {
		return err
	}
	if path != "" {
		return os.WriteFile(path, data, 0o644)
	}
	fmt.Println(string(data))
	return nil
}

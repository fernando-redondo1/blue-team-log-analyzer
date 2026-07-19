package main

import (
	"flag"
	"fmt"
	"os"

	"log-anomaly-detector/internal/detection"
	"log-anomaly-detector/internal/features"
	"log-anomaly-detector/internal/parser"
	"log-anomaly-detector/internal/report"
)

func main() {
	logType := flag.String("type", "ssh", "log format to parse: ssh or apache")
	jsonOutput := flag.String("json", "", "optional path to write JSON alerts")
	flag.Parse()

	if flag.NArg() != 1 {
		fmt.Println("usage: log-anomaly-detector [-type ssh|apache] [-json path] <logfile>")
		os.Exit(1)
	}

	logPath := flag.Arg(0)
	var events []parser.Event
	var err error

	switch *logType {
	case "ssh":
		events, err = parser.ParseSSHLog(logPath)
	case "apache":
		events, err = parser.ParseApacheLog(logPath)
	default:
		fmt.Printf("unsupported log type: %s\n", *logType)
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("failed to parse log: %v\n", err)
		os.Exit(1)
	}

	ipFeatures := features.BuildIPFeatures(events)
	alerts := detection.DetectAlerts(ipFeatures)

	if *jsonOutput != "" {
		if err := report.WriteJSON(alerts, *jsonOutput); err != nil {
			fmt.Printf("failed to write JSON: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Wrote %d alerts to %s\n", len(alerts), *jsonOutput)
		return
	}

	report.PrintAlerts(alerts)
}

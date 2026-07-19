package parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var apachePattern = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[(.+)\]\s+"(\S+)\s+(\S+)\s+([^\"]+)"\s+(\d{3})\s+(\d+|-)\s+"([^\"]*)"\s+"([^\"]*)"$`)

// ParseApacheLog parses a common Apache access log line into a normalized event.
func ParseApacheLog(path string) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var events []Event
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		match := apachePattern.FindStringSubmatch(line)
		if len(match) < 10 {
			continue
		}

		statusCode, err := strconv.Atoi(match[6])
		if err != nil {
			continue
		}

		events = append(events, Event{
			SourceIP:  match[1],
			Action:    "http_request",
			Success:   statusCode < 400,
			Username:  "",
			Port:      "",
			Protocol:  "http",
			Timestamp: parseApacheTimestamp(match[2]),
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan log: %w", err)
	}

	return events, nil
}

func parseApacheTimestamp(raw string) time.Time {
	parsed, err := time.Parse("02/Jan/2006:15:04:05 -0700", raw)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

package parser

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Event represents a normalized SSH authentication event.
type Event struct {
	Timestamp  time.Time
	SourceIP   string
	Username   string
	Action     string
	Success    bool
	Port       string
	Protocol   string
	Path       string
	StatusCode int
}

var sshPattern = regexp.MustCompile(`^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+sshd\[(\d+)\]:\s+(.+)$`)
var failedPasswordPattern = regexp.MustCompile(`^Failed password for (invalid user )?(\S+) from (\S+) port (\d+) (\S+)$`)
var acceptedPasswordPattern = regexp.MustCompile(`^Accepted password for (invalid user )?(\S+) from (\S+) port (\d+) (\S+)$`)
var invalidUserPattern = regexp.MustCompile(`^Invalid user (\S+) from (\S+)$`)

// ParseSSHLog reads an SSH auth log and returns normalized events.
func ParseSSHLog(path string) ([]Event, error) {
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
		match := sshPattern.FindStringSubmatch(line)
		if len(match) < 5 {
			continue
		}

		msg := match[4]
		event, ok := parseMessage(msg)
		if !ok {
			continue
		}
		event.Timestamp = time.Now()
		events = append(events, event)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan log: %w", err)
	}

	return events, nil
}

func parseMessage(msg string) (Event, bool) {
	switch {
	case strings.Contains(msg, "Failed password"):
		match := failedPasswordPattern.FindStringSubmatch(msg)
		if len(match) < 6 {
			return Event{}, false
		}
		return Event{
			SourceIP: match[3],
			Action:   "failed_password",
			Success:  false,
			Username: match[2],
			Port:     match[4],
			Protocol: "ssh",
		}, true
	case strings.Contains(msg, "Accepted password"):
		match := acceptedPasswordPattern.FindStringSubmatch(msg)
		if len(match) < 6 {
			return Event{}, false
		}
		return Event{
			SourceIP: match[3],
			Action:   "accepted_password",
			Success:  true,
			Username: match[2],
			Port:     match[4],
			Protocol: "ssh",
		}, true
	case strings.Contains(msg, "Invalid user"):
		match := invalidUserPattern.FindStringSubmatch(msg)
		if len(match) < 3 {
			return Event{}, false
		}
		return Event{
			SourceIP: match[2],
			Action:   "invalid_user",
			Success:  false,
			Username: match[1],
			Protocol: "ssh",
		}, true
	default:
		return Event{}, false
	}
}

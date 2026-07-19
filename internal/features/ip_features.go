package features

import (
	"log-anomaly-detector/internal/parser"
	"strings"
)

// IPFeatures summarizes suspicious behavior for a source IP.
type IPFeatures struct {
	SourceIP        string
	TotalEvents     int
	FailedEvents    int
	Successful      int
	DistinctUsers   int
	DistinctPaths   int
	FailureRatio    float64
	EventsPerMinute float64
	ErrorRate       float64
	HighRiskPaths   int
}

// BuildIPFeatures aggregates parser events by source IP.
func BuildIPFeatures(events []parser.Event) []IPFeatures {
	counts := make(map[string]*IPFeatures)
	for _, event := range events {
		feat := counts[event.SourceIP]
		if feat == nil {
			feat = &IPFeatures{SourceIP: event.SourceIP}
			counts[event.SourceIP] = feat
		}
		feat.TotalEvents++
		if !event.Success {
			feat.FailedEvents++
		} else {
			feat.Successful++
		}
		if event.Username != "" {
			feat.DistinctUsers++
		}
		if event.Path != "" {
			feat.DistinctPaths++
			if event.StatusCode >= 400 || strings.Contains(event.Path, "login") || strings.Contains(event.Path, "admin") || strings.Contains(event.Path, "wp") {
				feat.HighRiskPaths++
			}
		}
	}

	for _, feat := range counts {
		if feat.TotalEvents > 0 {
			feat.FailureRatio = float64(feat.FailedEvents) / float64(feat.TotalEvents)
			feat.ErrorRate = float64(feat.FailedEvents) / float64(feat.TotalEvents)
		}
		feat.EventsPerMinute = float64(feat.TotalEvents)
	}

	result := make([]IPFeatures, 0, len(counts))
	for _, feat := range counts {
		result = append(result, *feat)
	}
	return result
}

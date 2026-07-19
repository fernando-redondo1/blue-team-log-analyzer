package features

import (
	"testing"

	"log-anomaly-detector/internal/parser"
)

func TestBuildIPFeaturesTracksHTTPErrorsAndPaths(t *testing.T) {
	events := []parser.Event{
		{SourceIP: "10.0.0.3", Action: "http_request", Success: false, Path: "/admin", StatusCode: 404},
		{SourceIP: "10.0.0.3", Action: "http_request", Success: false, Path: "/login", StatusCode: 403},
		{SourceIP: "10.0.0.3", Action: "http_request", Success: true, Path: "/index", StatusCode: 200},
	}

	result := BuildIPFeatures(events)
	if len(result) != 1 {
		t.Fatalf("expected 1 feature set, got %d", len(result))
	}

	feat := result[0]
	if feat.ErrorRate != 2.0/3.0 {
		t.Fatalf("expected error rate 0.666..., got %.2f", feat.ErrorRate)
	}
	if feat.DistinctPaths != 3 {
		t.Fatalf("expected 3 distinct paths, got %d", feat.DistinctPaths)
	}
	if feat.HighRiskPaths != 2 {
		t.Fatalf("expected 2 high-risk paths, got %d", feat.HighRiskPaths)
	}
}

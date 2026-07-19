package detection

import "log-anomaly-detector/internal/features"

// Alert represents a suspicious IP with a severity score.
type Alert struct {
	SourceIP string
	Score    float64
	Reason   string
	Severity string
}

// DetectAlerts scores IP features and returns alerts.
func DetectAlerts(featuresList []features.IPFeatures) []Alert {
	var alerts []Alert
	for _, feat := range featuresList {
		score := 0.0
		reason := "normal traffic"
		severity := "low"

		if feat.FailedEvents >= 5 {
			score += 0.35
			reason = "multiple failed authentication attempts"
		}
		if feat.FailureRatio >= 0.7 {
			score += 0.25
			reason = "high failure ratio"
		}
		if feat.DistinctUsers >= 3 {
			score += 0.25
			reason = "multiple usernames targeted"
		}
		if feat.TotalEvents >= 8 {
			score += 0.15
			reason = "sustained burst of activity"
		}
		if feat.HighRiskPaths >= 2 {
			score += 0.2
			reason = "repeated access to risky paths"
		}
		if feat.ErrorRate >= 0.5 {
			score += 0.1
			reason = "error-heavy pattern"
		}
		if score >= 0.7 {
			severity = "high"
		} else if score >= 0.4 {
			severity = "medium"
		}
		if score > 0 {
			alerts = append(alerts, Alert{SourceIP: feat.SourceIP, Score: score, Reason: reason, Severity: severity})
		}
	}
	return alerts
}

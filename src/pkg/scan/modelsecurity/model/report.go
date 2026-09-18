// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package model

import (
	"encoding/json"
	"slices"
	"time"

	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
	"github.com/goharbor/harbor/src/pkg/scan/vuln"
)

// Report is the model security report produced by a model scanner adapter
// (mime type v1.MimeTypeModelSecurityReport). It lists static analysis findings
// (unsafe deserialization, embedded code, credentials, ...) for the files of a model artifact.
type Report struct {
	// Time of generating this report
	GeneratedAt string `json:"generated_at"`
	// Scanner of generating this report
	Scanner *v1.Scanner `json:"scanner"`
	// The highest severity of the findings, None when there are no findings
	Severity vuln.Severity `json:"severity"`
	// Aggregated counters
	Summary *Summary `json:"summary,omitempty"`
	// Findings list
	Findings []*Finding `json:"findings"`
}

// MarshalJSON dumps a nil slice of Findings as an empty slice
func (r *Report) MarshalJSON() ([]byte, error) {
	type Alias Report

	aux := &struct {
		*Alias
		Findings []*Finding `json:"findings"`
	}{
		Alias:    (*Alias)(r),
		Findings: r.Findings,
	}
	if aux.Findings == nil {
		aux.Findings = []*Finding{}
	}

	return json.Marshal(aux)
}

// Finding is one issue reported for a model file.
type Finding struct {
	// Identifier of the rule / check that produced the finding, e.g. "S201"
	ID string `json:"id"`
	// Severity of the finding
	Severity vuln.Severity `json:"severity"`
	// Short description
	Message string `json:"message"`
	// Explanation of the risk
	Why string `json:"why,omitempty"`
	// Path of the file inside the model artifact
	File string `json:"file,omitempty"`
	// Position inside the file (offset, layer, tensor name ...) as reported by the scanner
	Location string `json:"location,omitempty"`
	// The scanner engine / sub-scanner that produced the finding, e.g. "pickle"
	Scanner string `json:"scanner,omitempty"`
	// Scanner specific details
	Details map[string]any `json:"details,omitempty"`
	// Links to references
	Links []string `json:"links,omitempty"`
}

// Summary carries the aggregated counters of a report.
type Summary struct {
	Total        int      `json:"total"`
	Critical     int      `json:"critical"`
	High         int      `json:"high"`
	Medium       int      `json:"medium"`
	Low          int      `json:"low"`
	FilesScanned int      `json:"files_scanned"`
	BytesScanned int64    `json:"bytes_scanned"`
	Scanners     []string `json:"scanners,omitempty"`
}

// Recount rebuilds the severity counters from the findings, keeping the file/byte counters.
func (s *Summary) Recount(findings []*Finding) {
	s.Total, s.Critical, s.High, s.Medium, s.Low = 0, 0, 0, 0, 0
	for _, f := range findings {
		s.Total++
		switch f.Severity {
		case vuln.Critical:
			s.Critical++
		case vuln.High:
			s.High++
		case vuln.Medium:
			s.Medium++
		case vuln.Low:
			s.Low++
		}
	}
}

// Add accumulates the counters of another summary.
func (s *Summary) Add(another *Summary) {
	if another == nil {
		return
	}
	s.Total += another.Total
	s.Critical += another.Critical
	s.High += another.High
	s.Medium += another.Medium
	s.Low += another.Low
	s.FilesScanned += another.FilesScanned
	s.BytesScanned += another.BytesScanned
	for _, name := range another.Scanners {
		if !slices.Contains(s.Scanners, name) {
			s.Scanners = append(s.Scanners, name)
		}
	}
}

// MaxSeverity returns the highest severity of the findings, None when empty.
func MaxSeverity(findings []*Finding) vuln.Severity {
	severity := vuln.None
	for _, f := range findings {
		if f.Severity.Code() > severity.Code() {
			severity = f.Severity
		}
	}
	return severity
}

// Normalize fills the derived fields (severity, summary counters) from the findings so the
// stored report is consistent whatever the adapter sent.
func (r *Report) Normalize() {
	if r.Summary == nil {
		r.Summary = &Summary{}
	}
	r.Summary.Recount(r.Findings)
	r.Severity = MaxSeverity(r.Findings)
}

// Merge appends the findings of another report to this one and recomputes the derived fields.
// Used when several reports (e.g. of an index) are resolved together.
func (r *Report) Merge(another *Report) *Report {
	merged := &Report{
		GeneratedAt: r.GeneratedAt,
		Scanner:     r.Scanner,
		Summary:     &Summary{},
	}
	if another.GeneratedAt > merged.GeneratedAt {
		merged.GeneratedAt = another.GeneratedAt
		merged.Scanner = another.Scanner
	}
	merged.Findings = append(append([]*Finding{}, r.Findings...), another.Findings...)
	for _, s := range []*Summary{r.Summary, another.Summary} {
		if s != nil {
			merged.Summary.FilesScanned += s.FilesScanned
			merged.Summary.BytesScanned += s.BytesScanned
			merged.Summary.Add(&Summary{Scanners: s.Scanners})
		}
	}
	merged.Summary.Recount(merged.Findings)
	merged.Severity = MaxSeverity(merged.Findings)
	return merged
}

// ReportSummary is the summary of a model security report exposed as the
// scan_overview of an artifact. It has the same shape as the vulnerability
// NativeReportSummary (report_id, scan_status, severity, duration, summary with the
// counters per severity, ...) so API consumers and the Portal render the scan status of
// images and models alike.
type ReportSummary struct {
	ReportID        string                     `json:"report_id"`
	ScanStatus      string                     `json:"scan_status"`
	Severity        vuln.Severity              `json:"severity"`
	Duration        int64                      `json:"duration"`
	Summary         *vuln.VulnerabilitySummary `json:"summary,omitempty"`
	StartTime       time.Time                  `json:"start_time"`
	EndTime         time.Time                  `json:"end_time"`
	Scanner         *v1.Scanner                `json:"scanner,omitempty"`
	CompletePercent int                        `json:"complete_percent"`

	TotalCount    int `json:"-"`
	CompleteCount int `json:"-"`
}

// SeveritySummary converts the counters of the report to the vulnerability summary shape.
func (s *Summary) SeveritySummary() *vuln.VulnerabilitySummary {
	if s == nil {
		return nil
	}
	return &vuln.VulnerabilitySummary{
		Total: s.Total,
		Summary: vuln.SeveritySummary{
			vuln.Critical: s.Critical,
			vuln.High:     s.High,
			vuln.Medium:   s.Medium,
			vuln.Low:      s.Low,
		},
	}
}

// Merge merges two summaries (used for artifacts referencing several scanned artifacts).
func (sum *ReportSummary) Merge(another *ReportSummary) *ReportSummary {
	r := &ReportSummary{ReportID: sum.ReportID}

	r.StartTime = minTime(sum.StartTime, another.StartTime)
	r.EndTime = maxTime(sum.EndTime, another.EndTime)
	r.Duration = r.EndTime.Unix() - r.StartTime.Unix()
	if sum.StartTime.After(another.StartTime) {
		r.Scanner = sum.Scanner
	} else {
		r.Scanner = another.Scanner
	}

	r.TotalCount = sum.TotalCount + another.TotalCount
	r.CompleteCount = sum.CompleteCount + another.CompleteCount
	if r.TotalCount > 0 {
		r.CompletePercent = r.CompleteCount * 100 / r.TotalCount
	}

	r.ScanStatus = vuln.MergeScanStatus(sum.ScanStatus, another.ScanStatus)

	if sum.Severity.Code() >= another.Severity.Code() {
		r.Severity = sum.Severity
	} else {
		r.Severity = another.Severity
	}

	if sum.Summary != nil || another.Summary != nil {
		r.Summary = &vuln.VulnerabilitySummary{Summary: vuln.SeveritySummary{}}
		for _, s := range []*vuln.VulnerabilitySummary{sum.Summary, another.Summary} {
			if s == nil {
				continue
			}
			r.Summary.Total += s.Total
			for severity, count := range s.Summary {
				r.Summary.Summary[severity] += count
			}
		}
	}

	return r
}

func minTime(t1, t2 time.Time) time.Time {
	if t1.Before(t2) {
		return t1
	}
	return t2
}

func maxTime(t1, t2 time.Time) time.Time {
	if t1.After(t2) {
		return t1
	}
	return t2
}

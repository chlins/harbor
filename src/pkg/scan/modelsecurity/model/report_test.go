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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/jobservice/job"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
	"github.com/goharbor/harbor/src/pkg/scan/vuln"
)

const sampleReport = `{
  "generated_at": "2026-09-18T05:44:34Z",
  "scanner": {"name": "ModelAudit", "vendor": "Promptfoo", "version": "0.2.52"},
  "severity": "Critical",
  "summary": {"total": 2, "critical": 1, "high": 0, "medium": 1, "low": 0, "files_scanned": 2, "bytes_scanned": 89, "scanners": ["manifest", "pickle"]},
  "findings": [
    {"id": "S201", "severity": "Critical", "message": "Found REDUCE opcode invoking dangerous global: posix.system", "why": "system access", "file": "model.pkl", "location": "pos 64", "scanner": "pickle", "details": {"module": "posix"}, "links": ["https://www.promptfoo.dev/docs/model-audit/scanners/"]},
    {"id": "S309", "severity": "Medium", "message": "URL detected in model: http://evil.example/x", "file": "model.pkl", "scanner": "pickle"}
  ]
}`

func TestReportJSON(t *testing.T) {
	rp := &Report{}
	require.NoError(t, json.Unmarshal([]byte(sampleReport), rp))
	assert.Equal(t, vuln.Critical, rp.Severity)
	assert.Equal(t, "ModelAudit", rp.Scanner.Name)
	assert.Len(t, rp.Findings, 2)
	assert.Equal(t, "S201", rp.Findings[0].ID)
	assert.Equal(t, "posix", rp.Findings[0].Details["module"])

	// nil findings are marshalled as an empty list
	data, err := json.Marshal(&Report{Severity: vuln.None})
	require.NoError(t, err)
	assert.Contains(t, string(data), `"findings":[]`)
}

func TestNormalize(t *testing.T) {
	rp := &Report{Findings: []*Finding{{Severity: vuln.Low}, {Severity: vuln.High}, {Severity: vuln.High}}}
	rp.Normalize()
	assert.Equal(t, vuln.High, rp.Severity)
	assert.Equal(t, 3, rp.Summary.Total)
	assert.Equal(t, 2, rp.Summary.High)
	assert.Equal(t, 1, rp.Summary.Low)

	// inconsistent adapter data is corrected, file counters are kept
	rp = &Report{Severity: vuln.Critical, Summary: &Summary{Total: 9, FilesScanned: 4, BytesScanned: 10}}
	rp.Normalize()
	assert.Equal(t, vuln.None, rp.Severity)
	assert.Equal(t, 0, rp.Summary.Total)
	assert.Equal(t, 4, rp.Summary.FilesScanned)
	assert.EqualValues(t, 10, rp.Summary.BytesScanned)
}

func TestMaxSeverity(t *testing.T) {
	assert.Equal(t, vuln.None, MaxSeverity(nil))
	assert.Equal(t, vuln.Critical, MaxSeverity([]*Finding{{Severity: vuln.Medium}, {Severity: vuln.Critical}, {Severity: vuln.Low}}))
}

func TestReportMerge(t *testing.T) {
	r1 := &Report{
		GeneratedAt: "2026-01-01T00:00:00Z",
		Scanner:     &v1.Scanner{Name: "old"},
		Findings:    []*Finding{{ID: "A", Severity: vuln.Medium}},
		Summary:     &Summary{FilesScanned: 1, BytesScanned: 10, Scanners: []string{"pickle"}},
	}
	r2 := &Report{
		GeneratedAt: "2026-02-01T00:00:00Z",
		Scanner:     &v1.Scanner{Name: "new"},
		Findings:    []*Finding{{ID: "B", Severity: vuln.Critical}},
		Summary:     &Summary{FilesScanned: 2, BytesScanned: 20, Scanners: []string{"pickle", "gguf"}},
	}
	m := r1.Merge(r2)
	assert.Equal(t, "new", m.Scanner.Name)
	assert.Equal(t, vuln.Critical, m.Severity)
	assert.Len(t, m.Findings, 2)
	assert.Equal(t, 2, m.Summary.Total)
	assert.Equal(t, 1, m.Summary.Critical)
	assert.Equal(t, 1, m.Summary.Medium)
	assert.Equal(t, 3, m.Summary.FilesScanned)
	assert.EqualValues(t, 30, m.Summary.BytesScanned)
	assert.ElementsMatch(t, []string{"pickle", "gguf"}, m.Summary.Scanners)
}

func TestReportSummaryMerge(t *testing.T) {
	start := time.Now().Add(-time.Minute)
	s1 := &ReportSummary{
		ReportID:      "r1",
		ScanStatus:    job.SuccessStatus.String(),
		Severity:      vuln.Medium,
		StartTime:     start,
		EndTime:       start.Add(10 * time.Second),
		Scanner:       &v1.Scanner{Name: "s1"},
		Summary:       (&Summary{Total: 1, Medium: 1, FilesScanned: 1}).SeveritySummary(),
		TotalCount:    1,
		CompleteCount: 1,
	}
	s2 := &ReportSummary{
		ScanStatus:    job.RunningStatus.String(),
		Severity:      vuln.Critical,
		StartTime:     start.Add(time.Second),
		EndTime:       start.Add(30 * time.Second),
		Scanner:       &v1.Scanner{Name: "s2"},
		Summary:       (&Summary{Total: 1, Critical: 1, FilesScanned: 2}).SeveritySummary(),
		TotalCount:    1,
		CompleteCount: 0,
	}
	m := s1.Merge(s2)
	assert.Equal(t, "r1", m.ReportID)
	assert.Equal(t, job.RunningStatus.String(), m.ScanStatus)
	assert.Equal(t, vuln.Critical, m.Severity)
	assert.Equal(t, "s2", m.Scanner.Name)
	assert.Equal(t, 50, m.CompletePercent)
	assert.EqualValues(t, 30, m.Duration)
	assert.Equal(t, 2, m.Summary.Total)
	assert.Equal(t, 1, m.Summary.Summary[vuln.Critical])
	assert.Equal(t, 1, m.Summary.Summary[vuln.Medium])
}

func TestSeveritySummary(t *testing.T) {
	var s *Summary
	assert.Nil(t, s.SeveritySummary())
	vs := (&Summary{Total: 3, Critical: 2, Low: 1}).SeveritySummary()
	assert.Equal(t, 3, vs.Total)
	assert.Equal(t, 0, vs.Fixable)
	assert.Equal(t, 2, vs.Summary[vuln.Critical])
	assert.Equal(t, 1, vs.Summary[vuln.Low])
}

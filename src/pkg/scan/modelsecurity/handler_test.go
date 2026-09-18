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

package modelsecurity

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/goharbor/harbor/src/common/rbac"
	"github.com/goharbor/harbor/src/controller/artifact"
	"github.com/goharbor/harbor/src/controller/artifact/processor/cnai"
	scanCtl "github.com/goharbor/harbor/src/controller/scan"
	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/lib/orm"
	art "github.com/goharbor/harbor/src/pkg/artifact"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scanner"
	modelsecurity "github.com/goharbor/harbor/src/pkg/scan/modelsecurity/model"
	"github.com/goharbor/harbor/src/pkg/scan/report"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
	"github.com/goharbor/harbor/src/pkg/scan/vuln"
	"github.com/goharbor/harbor/src/pkg/task"
	scanCtlTest "github.com/goharbor/harbor/src/testing/controller/scan"
	ormtesting "github.com/goharbor/harbor/src/testing/lib/orm"
	"github.com/goharbor/harbor/src/testing/mock"
	reporttesting "github.com/goharbor/harbor/src/testing/pkg/scan/report"
	tasktesting "github.com/goharbor/harbor/src/testing/pkg/task"
)

const sampleReport = `{
  "generated_at": "2026-09-18T05:44:34Z",
  "scanner": {"name": "ModelAudit", "vendor": "Promptfoo", "version": "0.2.52"},
  "severity": "Low",
  "summary": {"total": 0, "files_scanned": 2, "bytes_scanned": 89, "scanners": ["manifest", "pickle"]},
  "findings": [
    {"id": "S201", "severity": "Critical", "message": "dangerous global: posix.system", "file": "model.pkl", "scanner": "pickle"},
    {"id": "S309", "severity": "Medium", "message": "URL detected", "file": "model.pkl", "scanner": "pickle"}
  ]
}`

var registration = &scanner.Registration{
	UUID: "uuid",
	Name: "modelaudit",
	Metadata: &v1.ScannerAdapterMetadata{
		Capabilities: []*v1.ScannerCapability{
			{Type: v1.ScanTypeModelSecurity, ConsumesMimeTypes: []string{v1.MimeTypeModelArtifact}, ProducesMimeTypes: []string{v1.MimeTypeModelSecurityReport, v1.MimeTypeModelRawReport}},
			{Type: v1.ScanTypeSbom, ConsumesMimeTypes: []string{v1.MimeTypeModelArtifact}, ProducesMimeTypes: []string{v1.MimeTypeSBOMReport}},
		},
	},
}

func modelArtifact() *artifact.Artifact {
	a := &artifact.Artifact{Artifact: art.Artifact{ID: 1, ProjectID: 1, RepositoryName: "library/model", Digest: "digest"}}
	a.Type = cnai.ArtifactTypeCNAI
	a.ManifestMediaType = v1.MimeTypeOCIArtifact
	a.ArtifactType = v1.MimeTypeModelArtifact
	return a
}

func scanTask(reportUUID string, status job.Status) *task.Task {
	return &task.Task{Status: status.String(), ExtraAttrs: map[string]any{"report_uuids": []any{reportUUID}}}
}

func TestHandlerStatics(t *testing.T) {
	h := &scanHandler{}
	assert.Equal(t, []string{v1.MimeTypeModelSecurityReport}, h.RequestProducesMineTypes())
	assert.Nil(t, h.RequestParameters())
	assert.Equal(t, job.ModelScanJobVendorType, h.JobVendorType())
	p, err := h.URLParameter(nil)
	require.NoError(t, err)
	assert.Equal(t, "", p)
	perms := h.RequiredPermissions()
	require.Len(t, perms, 2)
	assert.Equal(t, rbac.ResourceRepository, perms[0].Resource)
	assert.Equal(t, rbac.ActionPull, perms[0].Action)
	assert.Equal(t, rbac.ActionScannerPull, perms[1].Action)
}

func TestPostScan(t *testing.T) {
	h := &scanHandler{}

	// the report is normalized: severity and counters derived from the findings
	data, err := h.PostScan(nil, nil, &scan.Report{MimeType: v1.MimeTypeModelSecurityReport}, sampleReport, time.Time{}, nil)
	require.NoError(t, err)
	rp, err := report.ResolveData(v1.MimeTypeModelSecurityReport, []byte(data))
	require.NoError(t, err)
	mrp := rp.(*modelsecurity.Report)
	assert.Equal(t, vuln.Critical, mrp.Severity)
	assert.Equal(t, 2, mrp.Summary.Total)
	assert.Equal(t, 1, mrp.Summary.Critical)
	assert.Equal(t, 1, mrp.Summary.Medium)
	assert.Equal(t, 2, mrp.Summary.FilesScanned)
	assert.Len(t, mrp.Findings, 2)

	// raw reports are stored as is
	data, err = h.PostScan(nil, nil, &scan.Report{MimeType: v1.MimeTypeModelRawReport}, `{"issues": []}`, time.Time{}, nil)
	require.NoError(t, err)
	assert.Equal(t, `{"issues": []}`, data)

	// invalid report
	_, err = h.PostScan(nil, nil, &scan.Report{MimeType: v1.MimeTypeModelSecurityReport}, `not json`, time.Time{}, nil)
	assert.Error(t, err)
}

type HandlerTestSuite struct {
	suite.Suite
	handler        *scanHandler
	reportMgr      *reporttesting.Manager
	taskMgr        *tasktesting.Manager
	scanController *scanCtlTest.Controller
}

func (suite *HandlerTestSuite) SetupTest() {
	suite.reportMgr = &reporttesting.Manager{}
	suite.taskMgr = &tasktesting.Manager{}
	suite.scanController = &scanCtlTest.Controller{}
	suite.handler = &scanHandler{
		ReportMgrFunc:      func() report.Manager { return suite.reportMgr },
		TaskMgrFunc:        func() task.Manager { return suite.taskMgr },
		ScanControllerFunc: func() scanCtl.Controller { return suite.scanController },
		cloneCtx:           func(ctx context.Context) context.Context { return ctx },
	}
}

func TestHandlerTestSuite(t *testing.T) {
	suite.Run(t, &HandlerTestSuite{})
}

func (suite *HandlerTestSuite) TestMakePlaceHolder() {
	ctx := orm.NewContext(context.TODO(), &ormtesting.FakeOrmer{})

	// previous finished reports are deleted and one placeholder per produced mime type is created
	mock.OnAnything(suite.reportMgr, "GetBy").Return([]*scan.Report{{UUID: "old", MimeType: v1.MimeTypeModelSecurityReport}}, nil).Once()
	mock.OnAnything(suite.taskMgr, "ListScanTasksByReportUUID").Return([]*task.Task{scanTask("old", job.SuccessStatus)}, nil).Once()
	mock.OnAnything(suite.reportMgr, "Delete").Return(nil).Once()
	mock.OnAnything(suite.reportMgr, "Create").Return("new", nil).Twice()
	rps, err := suite.handler.MakePlaceHolder(ctx, modelArtifact(), registration)
	require.NoError(suite.T(), err)
	require.Len(suite.T(), rps, 2)
	assert.Equal(suite.T(), v1.MimeTypeModelSecurityReport, rps[0].MimeType)
	assert.Equal(suite.T(), v1.MimeTypeModelRawReport, rps[1].MimeType)
	assert.Equal(suite.T(), "new", rps[0].UUID)
	assert.Equal(suite.T(), "uuid", rps[0].RegistrationUUID)

	// a running scan is a conflict
	mock.OnAnything(suite.reportMgr, "GetBy").Return([]*scan.Report{{UUID: "old", MimeType: v1.MimeTypeModelSecurityReport}}, nil).Once()
	mock.OnAnything(suite.taskMgr, "ListScanTasksByReportUUID").Return([]*task.Task{scanTask("old", job.RunningStatus)}, nil).Once()
	_, err = suite.handler.MakePlaceHolder(ctx, modelArtifact(), registration)
	require.Error(suite.T(), err)

	// an image scanner registration produces no model report
	imageScanner := &scanner.Registration{UUID: "trivy", Metadata: &v1.ScannerAdapterMetadata{Capabilities: []*v1.ScannerCapability{
		{Type: v1.ScanTypeVulnerability, ConsumesMimeTypes: []string{v1.MimeTypeDockerArtifact}, ProducesMimeTypes: []string{v1.MimeTypeGenericVulnerabilityReport}},
	}}}
	_, err = suite.handler.MakePlaceHolder(ctx, modelArtifact(), imageScanner)
	require.Error(suite.T(), err)
}

func (suite *HandlerTestSuite) TestGetPlaceHolder() {
	mock.OnAnything(suite.reportMgr, "GetBy").Return([]*scan.Report{{UUID: "uuid"}}, nil).Once()
	rp, err := suite.handler.GetPlaceHolder(context.TODO(), "repo", "digest", "uuid", v1.MimeTypeModelSecurityReport)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), "uuid", rp.UUID)

	mock.OnAnything(suite.reportMgr, "GetBy").Return(nil, nil).Once()
	_, err = suite.handler.GetPlaceHolder(context.TODO(), "repo", "digest", "uuid", v1.MimeTypeModelSecurityReport)
	require.Error(suite.T(), err)

	mock.OnAnything(suite.reportMgr, "GetBy").Return(nil, fmt.Errorf("boom")).Once()
	_, err = suite.handler.GetPlaceHolder(context.TODO(), "repo", "digest", "uuid", v1.MimeTypeModelSecurityReport)
	require.Error(suite.T(), err)
}

func (suite *HandlerTestSuite) TestUpdate() {
	mock.OnAnything(suite.reportMgr, "UpdateReportData").Return(nil).Once()
	require.NoError(suite.T(), suite.handler.Update(context.TODO(), "uuid", sampleReport))
}

func (suite *HandlerTestSuite) TestGetSummary() {
	_, err := suite.handler.GetSummary(context.TODO(), nil, []string{v1.MimeTypeModelSecurityReport})
	require.Error(suite.T(), err)

	rp := &scan.Report{UUID: "uuid", MimeType: v1.MimeTypeModelSecurityReport, Status: job.SuccessStatus.String(), Report: sampleReport}
	mock.OnAnything(suite.scanController, "GetReport").Return([]*scan.Report{rp}, nil).Once()
	sum, err := suite.handler.GetSummary(context.TODO(), modelArtifact(), []string{v1.MimeTypeModelSecurityReport})
	require.NoError(suite.T(), err)
	require.Len(suite.T(), sum, 1)
	s := sum[v1.MimeTypeModelSecurityReport].(*modelsecurity.ReportSummary)
	assert.Equal(suite.T(), "uuid", s.ReportID)
	assert.Equal(suite.T(), job.SuccessStatus.String(), s.ScanStatus)
	assert.Equal(suite.T(), 100, s.CompletePercent)
	assert.Equal(suite.T(), "ModelAudit", s.Scanner.Name)
	// the stored report's own severity/summary are used (PostScan normalized them)
	assert.Equal(suite.T(), vuln.Low, s.Severity)
	assert.Equal(suite.T(), 2, s.Summary.FilesScanned)

	// running scan: status only
	running := &scan.Report{UUID: "uuid", MimeType: v1.MimeTypeModelSecurityReport, Status: job.RunningStatus.String()}
	mock.OnAnything(suite.scanController, "GetReport").Return([]*scan.Report{running}, nil).Once()
	sum, err = suite.handler.GetSummary(context.TODO(), modelArtifact(), []string{v1.MimeTypeModelSecurityReport})
	require.NoError(suite.T(), err)
	s = sum[v1.MimeTypeModelSecurityReport].(*modelsecurity.ReportSummary)
	assert.Equal(suite.T(), job.RunningStatus.String(), s.ScanStatus)
	assert.Equal(suite.T(), 0, s.CompletePercent)
	assert.Nil(suite.T(), s.Summary)

	// two reports of the same mime type are merged
	mock.OnAnything(suite.scanController, "GetReport").Return([]*scan.Report{rp, running}, nil).Once()
	sum, err = suite.handler.GetSummary(context.TODO(), modelArtifact(), []string{v1.MimeTypeModelSecurityReport})
	require.NoError(suite.T(), err)
	s = sum[v1.MimeTypeModelSecurityReport].(*modelsecurity.ReportSummary)
	assert.Equal(suite.T(), job.RunningStatus.String(), s.ScanStatus)
	assert.Equal(suite.T(), 50, s.CompletePercent)
}

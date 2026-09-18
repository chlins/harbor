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

// Package modelsecurity implements the scan handler for the model-security scan type: the
// reports produced by AI model scanners (e.g. ModelAudit) for CNCF model artifacts.
package modelsecurity

import (
	"context"
	"encoding/json"
	"time"

	"github.com/goharbor/harbor/src/common/rbac"
	"github.com/goharbor/harbor/src/controller/artifact"
	scanCtl "github.com/goharbor/harbor/src/controller/scan"
	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/jobservice/logger"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/lib/orm"
	"github.com/goharbor/harbor/src/pkg/permission/types"
	"github.com/goharbor/harbor/src/pkg/robot/model"
	scanJob "github.com/goharbor/harbor/src/pkg/scan"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scan"
	"github.com/goharbor/harbor/src/pkg/scan/dao/scanner"
	modelsecurity "github.com/goharbor/harbor/src/pkg/scan/modelsecurity/model"
	"github.com/goharbor/harbor/src/pkg/scan/report"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
	"github.com/goharbor/harbor/src/pkg/task"
)

func init() {
	scanJob.RegisterScanHanlder(v1.ScanTypeModelSecurity, &scanHandler{
		ReportMgrFunc:      func() report.Manager { return report.Mgr },
		TaskMgrFunc:        func() task.Manager { return task.Mgr },
		ScanControllerFunc: func() scanCtl.Controller { return scanCtl.DefaultController },
		cloneCtx:           orm.Clone,
	})
}

// scanHandler defines the handler for the model security scan
type scanHandler struct {
	ReportMgrFunc      func() report.Manager
	TaskMgrFunc        func() task.Manager
	ScanControllerFunc func() scanCtl.Controller
	cloneCtx           func(ctx context.Context) context.Context
}

// RequestProducesMineTypes returns the produces mime types requested from the scanner
func (h *scanHandler) RequestProducesMineTypes() []string {
	return []string{v1.MimeTypeModelSecurityReport}
}

// RequestParameters defines the parameters for scan request
func (h *scanHandler) RequestParameters() map[string]any {
	return nil
}

// RequiredPermissions defines the permission used by the scan robot account
func (h *scanHandler) RequiredPermissions() []*types.Policy {
	return []*types.Policy{
		{
			Resource: rbac.ResourceRepository,
			Action:   rbac.ActionPull,
		},
		{
			Resource: rbac.ResourceRepository,
			Action:   rbac.ActionScannerPull,
		},
	}
}

// PostScan validates and normalizes the report returned by the scanner before it is stored.
func (h *scanHandler) PostScan(_ job.Context, _ *v1.ScanRequest, origRp *scan.Report, rawReport string,
	_ time.Time, _ *model.Robot) (string, error) {
	if origRp.MimeType != v1.MimeTypeModelSecurityReport {
		// e.g. the raw report of the scanner, store as is
		return rawReport, nil
	}
	rp := &modelsecurity.Report{}
	if err := json.Unmarshal([]byte(rawReport), rp); err != nil {
		return "", errors.Wrap(err, "invalid model security report")
	}
	rp.Normalize()
	data, err := json.Marshal(rp)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// URLParameter the model security report doesn't require any scan report parameters
func (h *scanHandler) URLParameter(_ *v1.ScanRequest) (string, error) {
	return "", nil
}

// Update updates the report data in the database by UUID
func (h *scanHandler) Update(ctx context.Context, uuid string, rpt string) error {
	return h.ReportMgrFunc().UpdateReportData(ctx, uuid, rpt)
}

// MakePlaceHolder makes the report placeholders, one per produced mime type of the scanner
func (h *scanHandler) MakePlaceHolder(ctx context.Context, art *artifact.Artifact, r *scanner.Registration) ([]*scan.Report, error) {
	mimeTypes := r.GetProducesMimeTypes(scanJob.ArtifactMimeType(art), v1.ScanTypeModelSecurity)
	if len(mimeTypes) == 0 {
		return nil, errors.Errorf("scanner %s produces no model security report for %s", r.Name, art.Digest)
	}
	reportMgr := h.ReportMgrFunc()
	oldReports, err := reportMgr.GetBy(h.cloneCtx(ctx), art.Digest, r.UUID, mimeTypes)
	if err != nil {
		return nil, err
	}

	if err := h.assembleReports(ctx, oldReports...); err != nil {
		return nil, err
	}

	for _, oldReport := range oldReports {
		if !job.Status(oldReport.Status).Final() {
			return nil, errors.ConflictError(nil).WithMessagef("a previous scan process is %s", oldReport.Status)
		}
	}
	for _, oldReport := range oldReports {
		if err := reportMgr.Delete(ctx, oldReport.UUID); err != nil {
			return nil, err
		}
	}

	var reports []*scan.Report
	for _, pm := range mimeTypes {
		rpt := &scan.Report{
			Digest:           art.Digest,
			RegistrationUUID: r.UUID,
			MimeType:         pm,
		}

		create := func(ctx context.Context) error {
			reportUUID, err := reportMgr.Create(ctx, rpt)
			if err != nil {
				return err
			}
			rpt.UUID = reportUUID

			return nil
		}

		if err := orm.WithTransaction(create)(orm.SetTransactionOpNameToContext(ctx, "tx-make-model-report-placeholder")); err != nil {
			return nil, err
		}

		reports = append(reports, rpt)
	}

	return reports, nil
}

// GetPlaceHolder gets the report placeholder
func (h *scanHandler) GetPlaceHolder(ctx context.Context, _ string, artDigest, scannerUUID string, mimeType string) (*scan.Report, error) {
	reports, err := h.ReportMgrFunc().GetBy(ctx, artDigest, scannerUUID, []string{mimeType})
	if err != nil {
		logger.Errorf("failed to get report for artifact %s of mimetype %s, error %v", artDigest, mimeType, err)
		return nil, err
	}
	if len(reports) == 0 {
		return nil, errors.NotFoundError(nil).WithMessagef("no %s report found for artifact %s", mimeType, artDigest)
	}
	return reports[0], nil
}

// GetSummary gets the summaries of the reports, keyed by mime type
func (h *scanHandler) GetSummary(ctx context.Context, ar *artifact.Artifact, mimeTypes []string) (map[string]any, error) {
	if ar == nil {
		return nil, errors.New("no way to get report summaries for nil artifact")
	}
	rps, err := h.ScanControllerFunc().GetReport(ctx, ar, mimeTypes)
	if err != nil {
		return nil, err
	}
	summaries := make(map[string]any, len(rps))
	for _, rp := range rps {
		sum, err := report.GenerateSummary(rp)
		if err != nil {
			return nil, err
		}

		if s, ok := summaries[rp.MimeType]; ok {
			r, err := report.MergeSummary(rp.MimeType, s, sum)
			if err != nil {
				return nil, err
			}

			summaries[rp.MimeType] = r
		} else {
			summaries[rp.MimeType] = sum
		}
	}

	return summaries, nil
}

// JobVendorType returns the vendor type of the executions created for this scan type
func (h *scanHandler) JobVendorType() string {
	return job.ModelScanJobVendorType
}

func (h *scanHandler) assembleReports(ctx context.Context, reports ...*scan.Report) error {
	reportUUIDs := make([]string, len(reports))
	for i, rp := range reports {
		reportUUIDs[i] = rp.UUID
	}

	tasks, err := h.listScanTasks(ctx, reportUUIDs)
	if err != nil {
		return err
	}

	reportUUIDToTasks := map[string]*task.Task{}
	for _, t := range tasks {
		for _, reportUUID := range scanCtl.GetReportUUIDs(t.ExtraAttrs) {
			reportUUIDToTasks[reportUUID] = t
		}
	}

	for _, rp := range reports {
		if t, ok := reportUUIDToTasks[rp.UUID]; ok {
			rp.Status = t.Status
			rp.StartTime = t.StartTime
			rp.EndTime = t.EndTime
		} else {
			rp.Status = job.ErrorStatus.String()
		}
	}

	return nil
}

func (h *scanHandler) listScanTasks(ctx context.Context, reportUUIDs []string) ([]*task.Task, error) {
	taskMgr := h.TaskMgrFunc()
	var results []*task.Task
	for _, reportUUID := range reportUUIDs {
		tasks, err := taskMgr.ListScanTasksByReportUUID(h.cloneCtx(ctx), reportUUID)
		if err != nil {
			return nil, err
		}
		if len(tasks) == 0 {
			log.G(ctx).Warningf("task for the scan report %s not found", reportUUID)
			continue
		}
		results = append(results, tasks[0])
	}
	return results, nil
}

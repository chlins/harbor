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

// Package modelsync provides the controller of the model sync framework.
package modelsync

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/goharbor/harbor/src/common/secret"
	"github.com/goharbor/harbor/src/controller/event/operator"
	"github.com/goharbor/harbor/src/controller/project"
	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/modelsync/adapter"
	_ "github.com/goharbor/harbor/src/pkg/modelsync/adapter/huggingface" // register the model adapters
	"github.com/goharbor/harbor/src/pkg/modelsync/filter"
	modelsyncjob "github.com/goharbor/harbor/src/pkg/modelsync/job"
	"github.com/goharbor/harbor/src/pkg/modelsync/packer"
	"github.com/goharbor/harbor/src/pkg/modelsync/policy"
	pkgmodel "github.com/goharbor/harbor/src/pkg/modelsync/policy/model"
	"github.com/goharbor/harbor/src/pkg/reg"
	regmodel "github.com/goharbor/harbor/src/pkg/reg/model"
	"github.com/goharbor/harbor/src/pkg/scheduler"
	"github.com/goharbor/harbor/src/pkg/task"
)

const (
	callbackFuncName = "MODEL_SYNC_CALLBACK"
	// previewTimeout bounds the time spent resolving a source for preview.
	previewTimeout = 60 * time.Second
)

// Ctl is the global model sync controller.
var Ctl = NewController()

// Controller defines the operations of model sync.
type Controller interface {
	// PolicyCount returns the total count of policies according to the query
	PolicyCount(ctx context.Context, query *q.Query) (int64, error)
	// ListPolicies lists the policies according to the query
	ListPolicies(ctx context.Context, query *q.Query) ([]*Policy, error)
	// GetPolicy gets the specific policy
	GetPolicy(ctx context.Context, id int64) (*Policy, error)
	// CreatePolicy creates a policy
	CreatePolicy(ctx context.Context, policy *Policy) (int64, error)
	// UpdatePolicy updates the specific policy
	UpdatePolicy(ctx context.Context, policy *Policy, props ...string) error
	// DeletePolicy deletes the specific policy
	DeletePolicy(ctx context.Context, id int64) error
	// Start starts a sync of the policy and returns the execution ID
	Start(ctx context.Context, policy *Policy, trigger string) (int64, error)
	// Stop stops the execution
	Stop(ctx context.Context, executionID int64) error
	// ExecutionCount returns the total count of executions according to the query
	ExecutionCount(ctx context.Context, query *q.Query) (int64, error)
	// ListExecutions lists the executions according to the query
	ListExecutions(ctx context.Context, query *q.Query) ([]*Execution, error)
	// GetExecution gets the specific execution
	GetExecution(ctx context.Context, executionID int64) (*Execution, error)
	// TaskCount returns the total count of tasks according to the query
	TaskCount(ctx context.Context, query *q.Query) (int64, error)
	// ListTasks lists the tasks according to the query
	ListTasks(ctx context.Context, query *q.Query) ([]*Task, error)
	// GetTask gets the specific task
	GetTask(ctx context.Context, taskID int64) (*Task, error)
	// GetTaskLog gets the log of the specific task
	GetTaskLog(ctx context.Context, taskID int64) ([]byte, error)
	// Preview resolves a source and lists its files without importing
	Preview(ctx context.Context, req *PreviewRequest) (*Preview, error)
	// ListAdapterTypes lists the registry types that have a model adapter
	ListAdapterTypes(ctx context.Context) []string
}

// NewController creates a model sync controller.
func NewController() Controller {
	return &controller{
		policyMgr:  policy.Mgr,
		execMgr:    task.ExecMgr,
		taskMgr:    task.Mgr,
		regMgr:     reg.Mgr,
		projectCtl: project.Ctl,
		scheduler:  scheduler.Sched,
		newAdapter: adapter.Create,
	}
}

type controller struct {
	policyMgr  policy.Manager
	execMgr    task.ExecutionManager
	taskMgr    task.Manager
	regMgr     reg.Manager
	projectCtl project.Controller
	scheduler  scheduler.Scheduler
	newAdapter func(*regmodel.Registry) (adapter.Adapter, error)
}

func init() {
	callbackFunc := func(ctx context.Context, param string) error {
		params := make(map[string]any)
		if err := json.Unmarshal([]byte(param), &params); err != nil {
			return err
		}
		var policyID int64
		if id, ok := params["policy_id"].(float64); ok {
			policyID = int64(id)
		}
		if op, ok := params["operator"].(string); ok {
			ctx = context.WithValue(ctx, operator.ContextKey{}, op)
		}
		p, err := Ctl.GetPolicy(ctx, policyID)
		if err != nil {
			return err
		}
		_, err = Ctl.Start(ctx, p, task.ExecutionTriggerSchedule)
		return err
	}
	if err := scheduler.RegisterCallbackFunc(callbackFuncName, callbackFunc); err != nil {
		log.Errorf("failed to register the callback function for model sync: %v", err)
	}
	if err := task.RegisterCheckInProcessor(job.ModelSyncVendorType, defaultCheckInHandler.process); err != nil {
		log.Errorf("failed to register the check in processor for model sync: %v", err)
	}
}

// checkInHandler handles the result reported by the job.
type checkInHandler struct {
	taskMgr   task.Manager
	execMgr   task.ExecutionManager
	policyMgr policy.Manager
}

var defaultCheckInHandler = &checkInHandler{taskMgr: task.Mgr, execMgr: task.ExecMgr, policyMgr: policy.Mgr}

// process records the outcome on the task and advances the policy cursor.
func (h *checkInHandler) process(ctx context.Context, t *task.Task, sc *job.StatusChange) error {
	result := &modelsyncjob.Result{}
	if err := json.Unmarshal([]byte(sc.CheckIn), result); err != nil {
		return fmt.Errorf("failed to decode the check in data of model sync task %d: %w", t.ID, err)
	}
	if t.ExtraAttrs == nil {
		t.ExtraAttrs = map[string]any{}
	}
	t.ExtraAttrs["revision"] = result.Revision
	t.ExtraAttrs["digest"] = result.Digest
	t.ExtraAttrs["tags"] = result.Tags
	t.ExtraAttrs["files"] = result.Files
	t.ExtraAttrs["size"] = result.Size
	t.ExtraAttrs["skipped"] = result.Skipped
	t.ExtraAttrs["source_url"] = result.SourceURL
	if err := h.taskMgr.UpdateExtraAttrs(ctx, t.ID, t.ExtraAttrs); err != nil {
		return err
	}

	exec, err := h.execMgr.Get(ctx, t.ExecutionID)
	if err != nil {
		return err
	}
	if result.Revision == "" {
		return nil
	}
	return h.policyMgr.Update(ctx, &pkgmodel.Policy{ID: exec.VendorID, LastSyncedRevision: result.Revision}, "LastSyncedRevision")
}

func (c *controller) ListAdapterTypes(_ context.Context) []string {
	return adapter.ListRegisteredTypes()
}

func (c *controller) PolicyCount(ctx context.Context, query *q.Query) (int64, error) {
	return c.policyMgr.Count(ctx, query)
}

func (c *controller) ListPolicies(ctx context.Context, query *q.Query) ([]*Policy, error) {
	policies, err := c.policyMgr.List(ctx, query)
	if err != nil {
		return nil, err
	}
	result := make([]*Policy, 0, len(policies))
	for _, p := range policies {
		cp, err := c.populate(ctx, p)
		if err != nil {
			return nil, err
		}
		result = append(result, cp)
	}
	return result, nil
}

func (c *controller) GetPolicy(ctx context.Context, id int64) (*Policy, error) {
	p, err := c.policyMgr.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	return c.populate(ctx, p)
}

// populate fills in the registry and destination project of the policy. A
// missing registry or project doesn't fail the read, the fields are left sparse
// so the policy still shows up and can be fixed or deleted.
func (c *controller) populate(ctx context.Context, p *pkgmodel.Policy) (*Policy, error) {
	cp := &Policy{}
	if err := cp.From(p); err != nil {
		return nil, err
	}
	registry, err := c.regMgr.Get(ctx, p.RegistryID)
	if err != nil {
		if !errors.IsNotFoundErr(err) {
			return nil, err
		}
		log.Warningf("registry %d of model sync policy %d not found", p.RegistryID, p.ID)
	} else {
		// never expose the credential
		registry.Credential = nil
		cp.Registry = registry
	}
	proj, err := c.projectCtl.Get(ctx, p.DestProjectID)
	if err != nil {
		if !errors.IsNotFoundErr(err) {
			return nil, err
		}
		log.Warningf("project %d of model sync policy %d not found", p.DestProjectID, p.ID)
	} else {
		cp.DestProjectName = proj.Name
	}
	return cp, nil
}

func (c *controller) validate(ctx context.Context, p *Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	registry, err := c.regMgr.Get(ctx, p.Registry.ID)
	if err != nil {
		return err
	}
	if !adapter.HasFactory(registry.Type) {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessagef("registry %s (%s) has no model adapter, supported types: %s", registry.Name, registry.Type, strings.Join(adapter.ListRegisteredTypes(), ", "))
	}
	proj, err := c.projectCtl.Get(ctx, p.DestProjectID)
	if err != nil {
		return err
	}
	if proj.IsProxy() {
		return errors.New(nil).WithCode(errors.BadRequestCode).
			WithMessagef("project %s is a proxy cache project and cannot be the destination of model sync", proj.Name)
	}
	return nil
}

func (c *controller) CreatePolicy(ctx context.Context, p *Policy) (int64, error) {
	if err := c.validate(ctx, p); err != nil {
		return 0, err
	}
	dp, err := p.To()
	if err != nil {
		return 0, err
	}
	id, err := c.policyMgr.Create(ctx, dp)
	if err != nil {
		return 0, err
	}
	if p.IsScheduledTrigger() {
		if _, err := c.schedule(ctx, id, p.Cron); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (c *controller) schedule(ctx context.Context, policyID int64, cron string) (int64, error) {
	cbParams := map[string]any{
		"policy_id": policyID,
		// the operator of schedule job is harbor-jobservice
		"operator": secret.JobserviceUser,
	}
	return c.scheduler.Schedule(ctx, job.ModelSyncVendorType, policyID, "", cron, callbackFuncName, cbParams, map[string]any{})
}

func (c *controller) UpdatePolicy(ctx context.Context, p *Policy, props ...string) error {
	if err := c.validate(ctx, p); err != nil {
		return err
	}
	if err := c.scheduler.UnScheduleByVendor(ctx, job.ModelSyncVendorType, p.ID); err != nil {
		return err
	}
	dp, err := p.To()
	if err != nil {
		return err
	}
	// changing the source invalidates the cursor
	old, err := c.policyMgr.Get(ctx, p.ID)
	if err != nil {
		return err
	}
	if old.RegistryID != dp.RegistryID || old.SrcRepository != dp.SrcRepository || old.SrcRevision != dp.SrcRevision ||
		old.FileFilters != dp.FileFilters || old.DestProjectID != dp.DestProjectID || old.DestRepository != dp.DestRepository {
		dp.LastSyncedRevision = ""
		if len(props) > 0 {
			props = append(props, "LastSyncedRevision")
		}
	} else {
		dp.LastSyncedRevision = old.LastSyncedRevision
	}
	if err := c.policyMgr.Update(ctx, dp, props...); err != nil {
		return err
	}
	if p.IsScheduledTrigger() {
		if _, err := c.schedule(ctx, p.ID, p.Cron); err != nil {
			return err
		}
	}
	return nil
}

func (c *controller) DeletePolicy(ctx context.Context, id int64) error {
	if err := c.execMgr.DeleteByVendor(ctx, job.ModelSyncVendorType, id); err != nil {
		return err
	}
	if err := c.scheduler.UnScheduleByVendor(ctx, job.ModelSyncVendorType, id); err != nil {
		return err
	}
	return c.policyMgr.Delete(ctx, id)
}

func (c *controller) Start(ctx context.Context, p *Policy, trigger string) (int64, error) {
	if !p.Enabled {
		return 0, errors.New(nil).WithCode(errors.PreconditionCode).WithMessagef("the policy %d is disabled", p.ID)
	}
	// resolve the registry with credential and the project
	registry, err := c.regMgr.Get(ctx, p.Registry.ID)
	if err != nil {
		return 0, err
	}
	proj, err := c.projectCtl.Get(ctx, p.DestProjectID)
	if err != nil {
		return 0, err
	}
	p.DestProjectName = proj.Name

	extra := map[string]any{}
	if op := operator.FromContext(ctx); op != "" {
		extra["operator"] = op
	}
	// only one active sync per policy: count before creating the new execution
	// so the record created below isn't counted as "running" itself
	running, err := c.execMgr.Count(ctx, &q.Query{Keywords: map[string]any{
		"VendorType": job.ModelSyncVendorType,
		"VendorID":   p.ID,
		"Status":     job.RunningStatus.String(),
	}})
	if err != nil {
		return 0, err
	}
	id, err := c.execMgr.Create(ctx, job.ModelSyncVendorType, p.ID, trigger, extra)
	if err != nil {
		return 0, err
	}
	if running > 0 {
		if err := c.execMgr.MarkError(ctx, id, "Execution skipped: another sync of this policy is still in progress."); err != nil {
			return 0, err
		}
		return id, nil
	}

	params, err := (&modelsyncjob.Params{
		Registry:           registry,
		SrcRepository:      p.SrcRepository,
		SrcRevision:        p.SrcRevision,
		FileFilters:        p.FileFilters,
		DestRepository:     p.FullDestRepository(),
		LastSyncedRevision: p.LastSyncedRevision,
	}).ToJobParameters()
	if err != nil {
		_ = c.execMgr.MarkError(ctx, id, err.Error())
		return 0, err
	}
	j := &task.Job{
		Name:       job.ModelSyncVendorType,
		Metadata:   &job.Metadata{JobKind: job.KindGeneric},
		Parameters: params,
	}
	if _, err := c.taskMgr.Create(ctx, id, j, map[string]any{
		"src_repository":  p.SrcRepository,
		"src_revision":    p.SrcRevision,
		"dest_repository": p.FullDestRepository(),
	}); err != nil {
		_ = c.execMgr.MarkError(ctx, id, fmt.Sprintf("failed to create the sync task: %v", err))
		return 0, err
	}
	return id, nil
}

func (c *controller) Stop(ctx context.Context, id int64) error {
	if _, err := c.GetExecution(ctx, id); err != nil {
		return err
	}
	return c.execMgr.Stop(ctx, id)
}

func (c *controller) buildExecutionQuery(query *q.Query) *q.Query {
	query = q.MustClone(query)
	query.Keywords["VendorType"] = job.ModelSyncVendorType
	for _, k := range []string{"PolicyID", "policy_id"} {
		if v, exist := query.Keywords[k]; exist {
			query.Keywords["VendorID"] = v
			delete(query.Keywords, k)
		}
	}
	return query
}

func (c *controller) ExecutionCount(ctx context.Context, query *q.Query) (int64, error) {
	return c.execMgr.Count(ctx, c.buildExecutionQuery(query))
}

func (c *controller) ListExecutions(ctx context.Context, query *q.Query) ([]*Execution, error) {
	execs, err := c.execMgr.List(ctx, c.buildExecutionQuery(query))
	if err != nil {
		return nil, err
	}
	result := make([]*Execution, 0, len(execs))
	for _, e := range execs {
		result = append(result, convertExecution(e))
	}
	return result, nil
}

func (c *controller) GetExecution(ctx context.Context, id int64) (*Execution, error) {
	execs, err := c.execMgr.List(ctx, &q.Query{Keywords: map[string]any{
		"ID":         id,
		"VendorType": job.ModelSyncVendorType,
	}})
	if err != nil {
		return nil, err
	}
	if len(execs) == 0 {
		return nil, errors.New(nil).WithCode(errors.NotFoundCode).WithMessagef("model sync execution %d not found", id)
	}
	return convertExecution(execs[0]), nil
}

func (c *controller) TaskCount(ctx context.Context, query *q.Query) (int64, error) {
	query = q.MustClone(query)
	query.Keywords["VendorType"] = job.ModelSyncVendorType
	return c.taskMgr.Count(ctx, query)
}

func (c *controller) ListTasks(ctx context.Context, query *q.Query) ([]*Task, error) {
	query = q.MustClone(query)
	query.Keywords["VendorType"] = job.ModelSyncVendorType
	tasks, err := c.taskMgr.List(ctx, query)
	if err != nil {
		return nil, err
	}
	result := make([]*Task, 0, len(tasks))
	for _, t := range tasks {
		result = append(result, convertTask(t))
	}
	return result, nil
}

func (c *controller) GetTask(ctx context.Context, id int64) (*Task, error) {
	tasks, err := c.taskMgr.List(ctx, &q.Query{Keywords: map[string]any{
		"ID":         id,
		"VendorType": job.ModelSyncVendorType,
	}})
	if err != nil {
		return nil, err
	}
	if len(tasks) == 0 {
		return nil, errors.New(nil).WithCode(errors.NotFoundCode).WithMessagef("model sync task %d not found", id)
	}
	return convertTask(tasks[0]), nil
}

func (c *controller) GetTaskLog(ctx context.Context, id int64) ([]byte, error) {
	if _, err := c.GetTask(ctx, id); err != nil {
		return nil, err
	}
	return c.taskMgr.GetLog(ctx, id)
}

func (c *controller) Preview(ctx context.Context, req *PreviewRequest) (*Preview, error) {
	if req == nil || req.RegistryID <= 0 {
		return nil, errors.New(nil).WithCode(errors.BadRequestCode).WithMessage("registry id is required")
	}
	if strings.TrimSpace(req.SrcRepository) == "" {
		return nil, errors.New(nil).WithCode(errors.BadRequestCode).WithMessage("source repository is required")
	}
	if err := filter.Validate(req.FileFilters); err != nil {
		return nil, errors.New(err).WithCode(errors.BadRequestCode)
	}
	registry, err := c.regMgr.Get(ctx, req.RegistryID)
	if err != nil {
		return nil, err
	}
	src, err := c.newAdapter(registry)
	if err != nil {
		if errors.Is(err, adapter.ErrNotFound) {
			return nil, errors.New(nil).WithCode(errors.BadRequestCode).
				WithMessagef("registry %s (%s) has no model adapter", registry.Name, registry.Type)
		}
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, previewTimeout)
	defer cancel()
	rev, err := src.ResolveModel(ctx, adapter.ModelRef{
		Repository: strings.Trim(strings.TrimSpace(req.SrcRepository), "/"),
		Revision:   strings.TrimSpace(req.SrcRevision),
	})
	if err != nil {
		return nil, err
	}

	preview := &Preview{
		Repository: req.SrcRepository,
		Ref:        rev.Ref,
		Revision:   rev.ID,
		SourceURL:  rev.SourceURL,
		Metadata:   rev.Metadata,
		Tags:       packer.Tags(rev),
		Files:      make([]*PreviewFile, 0, len(rev.Files)),
	}
	for _, f := range rev.Files {
		if packer.IsIgnored(f.Path) {
			continue
		}
		matched := filter.Match(req.FileFilters, f.Path)
		preview.Files = append(preview.Files, &PreviewFile{
			Path:    f.Path,
			Size:    f.Size,
			SHA256:  f.SHA256,
			Type:    packer.InferFileType(f.Path, f.Size).String(),
			Matched: matched,
		})
		preview.TotalFiles++
		preview.TotalSize += f.Size
		if matched {
			preview.MatchedFiles++
			preview.MatchedSize += f.Size
		}
	}
	return preview, nil
}

func convertExecution(e *task.Execution) *Execution {
	exec := &Execution{
		ID:            e.ID,
		PolicyID:      e.VendorID,
		Status:        e.Status,
		StatusMessage: e.StatusMessage,
		Metrics:       e.Metrics,
		Trigger:       e.Trigger,
		StartTime:     e.StartTime,
		EndTime:       e.EndTime,
	}
	if op, ok := e.ExtraAttrs["operator"].(string); ok {
		exec.Operator = op
	}
	return exec
}

func convertTask(t *task.Task) *Task {
	tk := &Task{
		ID:            t.ID,
		ExecutionID:   t.ExecutionID,
		Status:        t.Status,
		StatusMessage: t.StatusMessage,
		RunCount:      t.RunCount,
		JobID:         t.JobID,
		CreationTime:  t.CreationTime,
		StartTime:     t.StartTime,
		UpdateTime:    t.UpdateTime,
		EndTime:       t.EndTime,
	}
	tk.SrcRepository = t.GetStringFromExtraAttrs("src_repository")
	tk.SrcRevision = t.GetStringFromExtraAttrs("src_revision")
	tk.DestRepository = t.GetStringFromExtraAttrs("dest_repository")
	tk.Revision = t.GetStringFromExtraAttrs("revision")
	tk.Digest = t.GetStringFromExtraAttrs("digest")
	tk.Files = t.GetInt64FromExtraAttrs("files")
	tk.Size = t.GetInt64FromExtraAttrs("size")
	tk.Skipped = t.GetBoolFromExtraAttrs("skipped")
	if tags, ok := t.ExtraAttrs["tags"].([]any); ok {
		for _, tag := range tags {
			if s, ok := tag.(string); ok {
				tk.Tags = append(tk.Tags, s)
			}
		}
	} else if tags, ok := t.ExtraAttrs["tags"].([]string); ok {
		tk.Tags = tags
	}
	return tk
}

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

package modelsync

import (
	"context"
	"encoding/json"
	"testing"

	tmock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"

	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/modelsync/adapter"
	modelsyncjob "github.com/goharbor/harbor/src/pkg/modelsync/job"
	pkgmodel "github.com/goharbor/harbor/src/pkg/modelsync/policy/model"
	"github.com/goharbor/harbor/src/pkg/project/models"
	regmodel "github.com/goharbor/harbor/src/pkg/reg/model"
	"github.com/goharbor/harbor/src/pkg/task"
	projecttesting "github.com/goharbor/harbor/src/testing/controller/project"
	"github.com/goharbor/harbor/src/testing/mock"
	adaptertesting "github.com/goharbor/harbor/src/testing/pkg/modelsync/adapter"
	policytesting "github.com/goharbor/harbor/src/testing/pkg/modelsync/policy"
	regtesting "github.com/goharbor/harbor/src/testing/pkg/reg"
	schedulertesting "github.com/goharbor/harbor/src/testing/pkg/scheduler"
	tasktesting "github.com/goharbor/harbor/src/testing/pkg/task"
)

type controllerTestSuite struct {
	suite.Suite
	ctl        *controller
	policyMgr  *policytesting.Manager
	execMgr    *tasktesting.ExecutionManager
	taskMgr    *tasktesting.Manager
	regMgr     *regtesting.Manager
	projectCtl *projecttesting.Controller
	scheduler  *schedulertesting.Scheduler
	adp        *adaptertesting.Adapter
}

func (s *controllerTestSuite) SetupTest() {
	s.policyMgr = &policytesting.Manager{}
	s.execMgr = &tasktesting.ExecutionManager{}
	s.taskMgr = &tasktesting.Manager{}
	s.regMgr = &regtesting.Manager{}
	s.projectCtl = &projecttesting.Controller{}
	s.scheduler = &schedulertesting.Scheduler{}
	s.adp = &adaptertesting.Adapter{}
	s.ctl = &controller{
		policyMgr:  s.policyMgr,
		execMgr:    s.execMgr,
		taskMgr:    s.taskMgr,
		regMgr:     s.regMgr,
		projectCtl: s.projectCtl,
		scheduler:  s.scheduler,
		newAdapter: func(r *regmodel.Registry) (adapter.Adapter, error) {
			if r.Type != regmodel.RegistryTypeHuggingFace {
				return nil, adapter.ErrNotFound
			}
			return s.adp, nil
		},
	}
}

func (s *controllerTestSuite) hfRegistry() *regmodel.Registry {
	return &regmodel.Registry{ID: 1, Name: "hf", Type: regmodel.RegistryTypeHuggingFace, URL: "https://huggingface.co",
		Credential: &regmodel.Credential{AccessSecret: "secret"}}
}

func (s *controllerTestSuite) policy() *Policy {
	return &Policy{
		Name:          "qwen",
		Enabled:       true,
		Registry:      &regmodel.Registry{ID: 1},
		SrcRepository: "Qwen/Qwen3-8B",
		FileFilters:   []string{"*.safetensors"},
		DestProjectID: 1,
		TriggerType:   pkgmodel.TriggerTypeManual,
	}
}

func (s *controllerTestSuite) TestListAndGetPolicy() {
	mock.OnAnything(s.policyMgr, "Count").Return(int64(1), nil)
	mock.OnAnything(s.policyMgr, "List").Return([]*pkgmodel.Policy{{ID: 1, Name: "qwen", RegistryID: 1, DestProjectID: 1, FileFilters: `["*.safetensors"]`}}, nil)
	mock.OnAnything(s.policyMgr, "Get").Return(&pkgmodel.Policy{ID: 1, Name: "qwen", RegistryID: 1, DestProjectID: 1, SrcRepository: "Qwen/Qwen3-8B"}, nil)
	mock.OnAnything(s.regMgr, "Get").Return(s.hfRegistry(), nil)
	mock.OnAnything(s.projectCtl, "Get").Return(&models.Project{ProjectID: 1, Name: "library"}, nil)

	n, err := s.ctl.PolicyCount(context.TODO(), nil)
	s.NoError(err)
	s.Equal(int64(1), n)

	policies, err := s.ctl.ListPolicies(context.TODO(), nil)
	s.Require().NoError(err)
	s.Require().Len(policies, 1)
	s.Equal([]string{"*.safetensors"}, policies[0].FileFilters)
	s.Equal("hf", policies[0].Registry.Name)
	s.Nil(policies[0].Registry.Credential, "credential must never be exposed")
	s.Equal("library", policies[0].DestProjectName)

	p, err := s.ctl.GetPolicy(context.TODO(), 1)
	s.Require().NoError(err)
	s.Equal("library/qwen/qwen3-8b", p.FullDestRepository())
}

func (s *controllerTestSuite) TestGetPolicyMissingRefs() {
	mock.OnAnything(s.policyMgr, "Get").Return(&pkgmodel.Policy{ID: 1, RegistryID: 9, DestProjectID: 9}, nil)
	mock.OnAnything(s.regMgr, "Get").Return(nil, errors.NotFoundError(nil))
	mock.OnAnything(s.projectCtl, "Get").Return(nil, errors.NotFoundError(nil))
	p, err := s.ctl.GetPolicy(context.TODO(), 1)
	s.Require().NoError(err)
	s.Equal(int64(9), p.Registry.ID)
	s.Equal("", p.DestProjectName)
}

func (s *controllerTestSuite) TestCreatePolicy() {
	mock.OnAnything(s.regMgr, "Get").Return(s.hfRegistry(), nil)
	mock.OnAnything(s.projectCtl, "Get").Return(&models.Project{ProjectID: 1, Name: "library"}, nil)
	mock.OnAnything(s.policyMgr, "Create").Return(int64(1), nil)
	mock.OnAnything(s.scheduler, "Schedule").Return(int64(1), nil)

	p := s.policy()
	p.TriggerType = pkgmodel.TriggerTypeScheduled
	p.Cron = "0 0 * * * *"
	id, err := s.ctl.CreatePolicy(context.TODO(), p)
	s.Require().NoError(err)
	s.Equal(int64(1), id)
	s.scheduler.AssertCalled(s.T(), "Schedule", tmock.Anything, job.ModelSyncVendorType, int64(1), "", "0 0 * * * *", callbackFuncName, tmock.Anything, tmock.Anything)
}

func (s *controllerTestSuite) TestCreatePolicyValidation() {
	// invalid policy
	_, err := s.ctl.CreatePolicy(context.TODO(), &Policy{})
	s.True(errors.IsErr(err, errors.BadRequestCode))

	// scheduled without cron
	p := s.policy()
	p.TriggerType = pkgmodel.TriggerTypeScheduled
	_, err = s.ctl.CreatePolicy(context.TODO(), p)
	s.True(errors.IsErr(err, errors.BadRequestCode))

	// manual with cron
	p = s.policy()
	p.Cron = "0 0 * * * *"
	_, err = s.ctl.CreatePolicy(context.TODO(), p)
	s.True(errors.IsErr(err, errors.BadRequestCode))

	// bad filter
	p = s.policy()
	p.FileFilters = []string{"["}
	_, err = s.ctl.CreatePolicy(context.TODO(), p)
	s.True(errors.IsErr(err, errors.BadRequestCode))

	// registry without model adapter
	mock.OnAnything(s.regMgr, "Get").Return(&regmodel.Registry{ID: 1, Type: regmodel.RegistryTypeDockerHub}, nil).Once()
	_, err = s.ctl.CreatePolicy(context.TODO(), s.policy())
	s.True(errors.IsErr(err, errors.BadRequestCode))

	// proxy cache project
	mock.OnAnything(s.regMgr, "Get").Return(s.hfRegistry(), nil)
	mock.OnAnything(s.projectCtl, "Get").Return(&models.Project{ProjectID: 1, Name: "proxy", RegistryID: 2}, nil).Once()
	_, err = s.ctl.CreatePolicy(context.TODO(), s.policy())
	s.True(errors.IsErr(err, errors.BadRequestCode))
}

func (s *controllerTestSuite) TestUpdatePolicy() {
	mock.OnAnything(s.regMgr, "Get").Return(s.hfRegistry(), nil)
	mock.OnAnything(s.projectCtl, "Get").Return(&models.Project{ProjectID: 1, Name: "library"}, nil)
	mock.OnAnything(s.scheduler, "UnScheduleByVendor").Return(nil)
	mock.OnAnything(s.scheduler, "Schedule").Return(int64(1), nil)
	mock.OnAnything(s.policyMgr, "Get").Return(&pkgmodel.Policy{ID: 1, RegistryID: 1, SrcRepository: "Qwen/Qwen3-8B", DestProjectID: 1, LastSyncedRevision: "abc", FileFilters: `["*.safetensors"]`}, nil)
	var updated *pkgmodel.Policy
	s.policyMgr.On("Update", tmock.Anything, tmock.Anything, tmock.Anything).Run(func(args tmock.Arguments) {
		updated = args.Get(1).(*pkgmodel.Policy)
	}).Return(nil)

	// same source: cursor kept
	p := s.policy()
	p.ID = 1
	s.Require().NoError(s.ctl.UpdatePolicy(context.TODO(), p))
	s.Equal("abc", updated.LastSyncedRevision)

	// source changed: cursor reset
	p.SrcRevision = "v2"
	p.TriggerType = pkgmodel.TriggerTypeScheduled
	p.Cron = "0 0 * * * *"
	s.Require().NoError(s.ctl.UpdatePolicy(context.TODO(), p))
	s.Equal("", updated.LastSyncedRevision)
	s.scheduler.AssertNumberOfCalls(s.T(), "Schedule", 1)
}

func (s *controllerTestSuite) TestDeletePolicy() {
	mock.OnAnything(s.execMgr, "DeleteByVendor").Return(nil)
	mock.OnAnything(s.scheduler, "UnScheduleByVendor").Return(nil)
	mock.OnAnything(s.policyMgr, "Delete").Return(nil)
	s.NoError(s.ctl.DeletePolicy(context.TODO(), 1))
	s.execMgr.AssertCalled(s.T(), "DeleteByVendor", tmock.Anything, job.ModelSyncVendorType, int64(1))
}

func (s *controllerTestSuite) TestStart() {
	mock.OnAnything(s.regMgr, "Get").Return(s.hfRegistry(), nil)
	mock.OnAnything(s.projectCtl, "Get").Return(&models.Project{ProjectID: 1, Name: "library"}, nil)
	// the running count must be taken before the new execution is created,
	// otherwise the new record counts itself and every run is skipped
	created := false
	s.execMgr.On("Count", tmock.Anything, tmock.Anything).Run(func(tmock.Arguments) {
		s.False(created, "Count must be called before Create")
	}).Return(int64(0), nil)
	s.execMgr.On("Create", tmock.Anything, tmock.Anything, tmock.Anything, tmock.Anything, tmock.Anything).Run(func(tmock.Arguments) {
		created = true
	}).Return(int64(10), nil)
	var createdJob *task.Job
	s.taskMgr.On("Create", tmock.Anything, int64(10), tmock.Anything, tmock.Anything).Run(func(args tmock.Arguments) {
		createdJob = args.Get(2).(*task.Job)
	}).Return(int64(11), nil)

	p := s.policy()
	p.ID = 1
	p.LastSyncedRevision = "abc"
	id, err := s.ctl.Start(context.TODO(), p, task.ExecutionTriggerManual)
	s.Require().NoError(err)
	s.Equal(int64(10), id)
	s.Require().NotNil(createdJob)
	s.Equal(job.ModelSyncVendorType, createdJob.Name)
	s.Equal("Qwen/Qwen3-8B", createdJob.Parameters[modelsyncjob.ParamSrcRepository])
	s.Equal("library/qwen/qwen3-8b", createdJob.Parameters[modelsyncjob.ParamDestRepository])
	s.Equal("abc", createdJob.Parameters[modelsyncjob.ParamLastSyncedRevision])
	s.Equal(`["*.safetensors"]`, createdJob.Parameters[modelsyncjob.ParamFileFilters])
	reg := &regmodel.Registry{}
	s.Require().NoError(json.Unmarshal([]byte(createdJob.Parameters[modelsyncjob.ParamRegistry].(string)), reg))
	s.Equal("secret", reg.Credential.AccessSecret, "the job needs the credential")

	// disabled
	p.Enabled = false
	_, err = s.ctl.Start(context.TODO(), p, task.ExecutionTriggerManual)
	s.True(errors.IsErr(err, errors.PreconditionCode))
}

func (s *controllerTestSuite) TestStartSkippedWhenRunning() {
	mock.OnAnything(s.regMgr, "Get").Return(s.hfRegistry(), nil)
	mock.OnAnything(s.projectCtl, "Get").Return(&models.Project{ProjectID: 1, Name: "library"}, nil)
	mock.OnAnything(s.execMgr, "Create").Return(int64(10), nil)
	mock.OnAnything(s.execMgr, "Count").Return(int64(1), nil)
	mock.OnAnything(s.execMgr, "MarkError").Return(nil)
	p := s.policy()
	p.ID = 1
	id, err := s.ctl.Start(context.TODO(), p, task.ExecutionTriggerManual)
	s.Require().NoError(err)
	s.Equal(int64(10), id)
	s.execMgr.AssertCalled(s.T(), "MarkError", tmock.Anything, int64(10), tmock.Anything)
	s.taskMgr.AssertNotCalled(s.T(), "Create")
}

func (s *controllerTestSuite) TestExecutionsAndTasks() {
	mock.OnAnything(s.execMgr, "List").Return([]*task.Execution{{ID: 10, VendorID: 1, VendorType: job.ModelSyncVendorType, ExtraAttrs: map[string]any{"operator": "admin"}}}, nil)
	mock.OnAnything(s.execMgr, "Count").Return(int64(1), nil)
	mock.OnAnything(s.execMgr, "Stop").Return(nil)
	mock.OnAnything(s.taskMgr, "List").Return([]*task.Task{{ID: 11, ExecutionID: 10, ExtraAttrs: map[string]any{
		"src_repository": "Qwen/Qwen3-8B", "dest_repository": "library/qwen/qwen3-8b", "revision": "abc", "digest": "sha256:x",
		"tags": []any{"sha-abc", "main"}, "files": float64(3), "size": float64(100), "skipped": false,
	}}}, nil)
	mock.OnAnything(s.taskMgr, "Count").Return(int64(1), nil)
	mock.OnAnything(s.taskMgr, "GetLog").Return([]byte("log"), nil)

	n, err := s.ctl.ExecutionCount(context.TODO(), &q.Query{Keywords: map[string]any{"policy_id": 1}})
	s.NoError(err)
	s.Equal(int64(1), n)
	execs, err := s.ctl.ListExecutions(context.TODO(), nil)
	s.Require().NoError(err)
	s.Equal("admin", execs[0].Operator)
	exec, err := s.ctl.GetExecution(context.TODO(), 10)
	s.Require().NoError(err)
	s.Equal(int64(1), exec.PolicyID)
	s.NoError(s.ctl.Stop(context.TODO(), 10))

	n, err = s.ctl.TaskCount(context.TODO(), nil)
	s.NoError(err)
	s.Equal(int64(1), n)
	tasks, err := s.ctl.ListTasks(context.TODO(), nil)
	s.Require().NoError(err)
	s.Equal([]string{"sha-abc", "main"}, tasks[0].Tags)
	s.Equal(int64(3), tasks[0].Files)
	s.Equal("sha256:x", tasks[0].Digest)
	t, err := s.ctl.GetTask(context.TODO(), 11)
	s.Require().NoError(err)
	s.Equal("library/qwen/qwen3-8b", t.DestRepository)
	l, err := s.ctl.GetTaskLog(context.TODO(), 11)
	s.NoError(err)
	s.Equal("log", string(l))
}

func (s *controllerTestSuite) TestGetExecutionNotFound() {
	mock.OnAnything(s.execMgr, "List").Return([]*task.Execution{}, nil)
	mock.OnAnything(s.taskMgr, "List").Return([]*task.Task{}, nil)
	_, err := s.ctl.GetExecution(context.TODO(), 1)
	s.True(errors.IsNotFoundErr(err))
	_, err = s.ctl.GetTask(context.TODO(), 1)
	s.True(errors.IsNotFoundErr(err))
}

func (s *controllerTestSuite) TestPreview() {
	mock.OnAnything(s.regMgr, "Get").Return(s.hfRegistry(), nil)
	mock.OnAnything(s.adp, "ResolveModel").Return(&adapter.Revision{
		Ref: "main", ID: "71034c5d8bde858ff824298bdedc65515b97d2b9", SourceURL: "https://huggingface.co/Qwen/Qwen3-8B/tree/x",
		Metadata: map[string]string{"license": "apache-2.0"},
		Files: []adapter.File{
			{Path: ".gitattributes", Size: 1},
			{Path: "README.md", Size: 10},
			{Path: "model.safetensors", Size: 100, SHA256: "aaa"},
		},
	}, nil)

	_, err := s.ctl.Preview(context.TODO(), nil)
	s.True(errors.IsErr(err, errors.BadRequestCode))
	_, err = s.ctl.Preview(context.TODO(), &PreviewRequest{RegistryID: 1})
	s.True(errors.IsErr(err, errors.BadRequestCode))

	preview, err := s.ctl.Preview(context.TODO(), &PreviewRequest{RegistryID: 1, SrcRepository: "Qwen/Qwen3-8B", FileFilters: []string{"*.safetensors"}})
	s.Require().NoError(err)
	s.Equal("71034c5d8bde858ff824298bdedc65515b97d2b9", preview.Revision)
	s.Equal([]string{"sha-71034c5d8bde", "main"}, preview.Tags)
	s.Require().Len(preview.Files, 2, ".gitattributes is skipped")
	s.Equal(int64(2), preview.TotalFiles)
	s.Equal(int64(110), preview.TotalSize)
	s.Equal(int64(1), preview.MatchedFiles)
	s.Equal(int64(100), preview.MatchedSize)
	s.Equal("weight", preview.Files[1].Type)
	s.True(preview.Files[1].Matched)
	s.False(preview.Files[0].Matched)

	// registry without adapter
	s.regMgr = &regtesting.Manager{}
	s.ctl.regMgr = s.regMgr
	mock.OnAnything(s.regMgr, "Get").Return(&regmodel.Registry{ID: 2, Type: regmodel.RegistryTypeDockerHub}, nil)
	_, err = s.ctl.Preview(context.TODO(), &PreviewRequest{RegistryID: 2, SrcRepository: "a/b"})
	s.True(errors.IsErr(err, errors.BadRequestCode))
}

func (s *controllerTestSuite) TestCheckIn() {
	h := &checkInHandler{taskMgr: s.taskMgr, execMgr: s.execMgr, policyMgr: s.policyMgr}
	var attrs map[string]any
	s.taskMgr.On("UpdateExtraAttrs", tmock.Anything, int64(11), tmock.Anything).Run(func(args tmock.Arguments) {
		attrs = args.Get(2).(map[string]any)
	}).Return(nil)
	mock.OnAnything(s.execMgr, "Get").Return(&task.Execution{ID: 10, VendorID: 1}, nil)
	var updated *pkgmodel.Policy
	s.policyMgr.On("Update", tmock.Anything, tmock.Anything, "LastSyncedRevision").Run(func(args tmock.Arguments) {
		updated = args.Get(1).(*pkgmodel.Policy)
	}).Return(nil)

	result, _ := json.Marshal(&modelsyncjob.Result{Revision: "abc", Digest: "sha256:x", Tags: []string{"sha-abc"}, Files: 2, Size: 10})
	err := h.process(context.TODO(), &task.Task{ID: 11, ExecutionID: 10}, &job.StatusChange{CheckIn: string(result)})
	s.Require().NoError(err)
	s.Equal("abc", attrs["revision"])
	s.Equal("sha256:x", attrs["digest"])
	s.Require().NotNil(updated)
	s.Equal(int64(1), updated.ID)
	s.Equal("abc", updated.LastSyncedRevision)

	s.Error(h.process(context.TODO(), &task.Task{ID: 11}, &job.StatusChange{CheckIn: "bad"}))
}

func (s *controllerTestSuite) TestListAdapterTypes() {
	s.Contains(s.ctl.ListAdapterTypes(context.TODO()), regmodel.RegistryTypeHuggingFace)
}

func TestControllerTestSuite(t *testing.T) {
	suite.Run(t, &controllerTestSuite{})
}

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
	"strings"
	"time"

	"github.com/goharbor/harbor/src/common/utils"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/pkg/modelsync/filter"
	pkgmodel "github.com/goharbor/harbor/src/pkg/modelsync/policy/model"
	"github.com/goharbor/harbor/src/pkg/reg/model"
	"github.com/goharbor/harbor/src/pkg/task/dao"
)

// Policy is the controller-level model sync policy, with the source registry and
// destination project populated.
type Policy struct {
	ID          int64
	Name        string
	Description string
	Creator     string
	Enabled     bool
	// Registry is the source model hub registered in registry management.
	Registry *model.Registry
	// SrcRepository is the hub-side repository, e.g. "Qwen/Qwen3-8B".
	SrcRepository string
	// SrcRevision is the branch/tag/commit expression; empty means the default branch.
	SrcRevision string
	// FileFilters are doublestar patterns; empty means all files.
	FileFilters []string
	// DestProjectID is the destination project.
	DestProjectID int64
	// DestProjectName is populated when reading a policy.
	DestProjectName string
	// DestRepository is the repository inside the destination project; defaults
	// to a name derived from the source repository.
	DestRepository string
	// TriggerType is "manual" or "scheduled".
	TriggerType string
	// Cron is the cron expression when TriggerType is "scheduled".
	Cron string
	// LastSyncedRevision is the idempotence cursor.
	LastSyncedRevision string
	CreationTime       time.Time
	UpdateTime         time.Time
}

// IsScheduledTrigger returns whether the policy has a cron trigger.
func (p *Policy) IsScheduledTrigger() bool {
	return p.TriggerType == pkgmodel.TriggerTypeScheduled
}

// EffectiveDestRepository returns the destination repository inside the project.
func (p *Policy) EffectiveDestRepository() string {
	if r := strings.Trim(strings.TrimSpace(p.DestRepository), "/"); r != "" {
		return r
	}
	return pkgmodel.DefaultDestRepository(p.SrcRepository)
}

// FullDestRepository returns "<project>/<repository>".
func (p *Policy) FullDestRepository() string {
	return p.DestProjectName + "/" + p.EffectiveDestRepository()
}

// Validate validates the policy.
func (p *Policy) Validate() error {
	if len(strings.TrimSpace(p.Name)) == 0 {
		return errors.New(nil).WithCode(errors.BadRequestCode).WithMessage("name cannot be empty")
	}
	if len(p.Name) > 256 {
		return errors.New(nil).WithCode(errors.BadRequestCode).WithMessage("name is too long")
	}
	if p.Registry == nil || p.Registry.ID <= 0 {
		return errors.New(nil).WithCode(errors.BadRequestCode).WithMessage("source registry is required")
	}
	if len(strings.TrimSpace(p.SrcRepository)) == 0 {
		return errors.New(nil).WithCode(errors.BadRequestCode).WithMessage("source repository cannot be empty")
	}
	if p.DestProjectID <= 0 {
		return errors.New(nil).WithCode(errors.BadRequestCode).WithMessage("destination project is required")
	}
	if err := filter.Validate(p.FileFilters); err != nil {
		return errors.New(err).WithCode(errors.BadRequestCode)
	}
	switch p.TriggerType {
	case pkgmodel.TriggerTypeManual:
		if strings.TrimSpace(p.Cron) != "" {
			return errors.New(nil).WithCode(errors.BadRequestCode).WithMessage("cron must be empty for manual trigger")
		}
	case pkgmodel.TriggerTypeScheduled:
		if strings.TrimSpace(p.Cron) == "" {
			return errors.New(nil).WithCode(errors.BadRequestCode).WithMessage("cron is required for scheduled trigger")
		}
		if err := utils.ValidateCronString(p.Cron); err != nil {
			return errors.New(nil).WithCode(errors.BadRequestCode).WithMessagef("invalid cron %q: %v", p.Cron, err)
		}
	default:
		return errors.New(nil).WithCode(errors.BadRequestCode).WithMessagef("invalid trigger type %q", p.TriggerType)
	}
	return nil
}

// From converts the DAO model to the controller model.
func (p *Policy) From(policy *pkgmodel.Policy) error {
	if policy == nil {
		return nil
	}
	filters, err := policy.GetFileFilters()
	if err != nil {
		return err
	}
	p.ID = policy.ID
	p.Name = policy.Name
	p.Description = policy.Description
	p.Creator = policy.Creator
	p.Enabled = policy.Enabled
	p.Registry = &model.Registry{ID: policy.RegistryID}
	p.SrcRepository = policy.SrcRepository
	p.SrcRevision = policy.SrcRevision
	p.FileFilters = filters
	p.DestProjectID = policy.DestProjectID
	p.DestRepository = policy.DestRepository
	p.TriggerType = policy.TriggerType
	p.Cron = policy.Cron
	p.LastSyncedRevision = policy.LastSyncedRevision
	p.CreationTime = policy.CreationTime
	p.UpdateTime = policy.UpdateTime
	return nil
}

// To converts the controller model to the DAO model.
func (p *Policy) To() (*pkgmodel.Policy, error) {
	policy := &pkgmodel.Policy{
		ID:                 p.ID,
		Name:               strings.TrimSpace(p.Name),
		Description:        p.Description,
		Creator:            p.Creator,
		Enabled:            p.Enabled,
		SrcRepository:      strings.Trim(strings.TrimSpace(p.SrcRepository), "/"),
		SrcRevision:        strings.TrimSpace(p.SrcRevision),
		DestProjectID:      p.DestProjectID,
		DestRepository:     strings.Trim(strings.TrimSpace(p.DestRepository), "/"),
		TriggerType:        p.TriggerType,
		Cron:               strings.TrimSpace(p.Cron),
		LastSyncedRevision: p.LastSyncedRevision,
		CreationTime:       p.CreationTime,
		UpdateTime:         p.UpdateTime,
	}
	if p.Registry != nil {
		policy.RegistryID = p.Registry.ID
	}
	if err := policy.SetFileFilters(p.FileFilters); err != nil {
		return nil, err
	}
	return policy, nil
}

// Execution is the model sync execution.
type Execution struct {
	ID            int64
	PolicyID      int64
	Status        string
	StatusMessage string
	Metrics       *dao.Metrics
	Trigger       string
	Operator      string
	StartTime     time.Time
	EndTime       time.Time
}

// Task is the model sync task, one per execution.
type Task struct {
	ID            int64
	ExecutionID   int64
	Status        string
	StatusMessage string
	RunCount      int32
	JobID         string
	// SrcRepository is the hub repository being synced.
	SrcRepository string
	// SrcRevision is the revision expression requested.
	SrcRevision string
	// DestRepository is the full destination repository.
	DestRepository string
	// Revision is the resolved immutable upstream revision, populated when the job reports back.
	Revision string
	// Digest of the pushed artifact, populated when the job reports back.
	Digest string
	// Tags applied to the artifact, populated when the job reports back.
	Tags []string
	// Files is the number of files synced.
	Files int64
	// Size is the total size of the pushed artifact.
	Size int64
	// Skipped is true when the revision was already synced.
	Skipped      bool
	CreationTime time.Time
	StartTime    time.Time
	UpdateTime   time.Time
	EndTime      time.Time
}

// PreviewRequest resolves a source without importing it.
type PreviewRequest struct {
	RegistryID    int64
	SrcRepository string
	SrcRevision   string
	FileFilters   []string
}

// PreviewFile is one file of the preview.
type PreviewFile struct {
	Path    string
	Size    int64
	SHA256  string
	Type    string
	Matched bool
}

// Preview is the result of resolving a source.
type Preview struct {
	Repository   string
	Ref          string
	Revision     string
	SourceURL    string
	Metadata     map[string]string
	Files        []*PreviewFile
	MatchedFiles int64
	MatchedSize  int64
	TotalFiles   int64
	TotalSize    int64
	Tags         []string
}

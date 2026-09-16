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

// Package job implements the MODEL_SYNC jobservice job.
package job

import (
	"encoding/json"
	"strings"

	commonhttp "github.com/goharbor/harbor/src/common/http"
	"github.com/goharbor/harbor/src/common/http/modifier/auth"
	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/lib/config"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/pkg/modelsync/adapter"
	// register the model adapters
	_ "github.com/goharbor/harbor/src/pkg/modelsync/adapter/huggingface"
	"github.com/goharbor/harbor/src/pkg/modelsync/filter"
	"github.com/goharbor/harbor/src/pkg/modelsync/packer"
	regmodel "github.com/goharbor/harbor/src/pkg/reg/model"
	"github.com/goharbor/harbor/src/pkg/registry"
)

const (
	// ParamRegistry is the JSON encoded source registry (with credential).
	ParamRegistry = "registry"
	// ParamSrcRepository is the hub-side repository.
	ParamSrcRepository = "src_repository"
	// ParamSrcRevision is the revision expression (branch/tag/commit), empty means default.
	ParamSrcRevision = "src_revision"
	// ParamFileFilters is the JSON encoded array of doublestar patterns.
	ParamFileFilters = "file_filters"
	// ParamDestRepository is the full destination repository, e.g. "library/qwen/qwen3-8b".
	ParamDestRepository = "dest_repository"
	// ParamLastSyncedRevision is the policy cursor, used to skip unchanged revisions.
	ParamLastSyncedRevision = "last_synced_revision"
)

// Params are the typed parameters of the job.
type Params struct {
	Registry           *regmodel.Registry
	SrcRepository      string
	SrcRevision        string
	FileFilters        []string
	DestRepository     string
	LastSyncedRevision string
}

// ToJobParameters encodes the params for the jobservice.
func (p *Params) ToJobParameters() (job.Parameters, error) {
	reg, err := json.Marshal(p.Registry)
	if err != nil {
		return nil, err
	}
	filters, err := json.Marshal(p.FileFilters)
	if err != nil {
		return nil, err
	}
	return job.Parameters{
		ParamRegistry:           string(reg),
		ParamSrcRepository:      p.SrcRepository,
		ParamSrcRevision:        p.SrcRevision,
		ParamFileFilters:        string(filters),
		ParamDestRepository:     p.DestRepository,
		ParamLastSyncedRevision: p.LastSyncedRevision,
	}, nil
}

// Result is reported back to core through the check-in mechanism.
type Result struct {
	// Revision is the immutable upstream revision that was synced.
	Revision string `json:"revision"`
	// Ref is the revision expression as requested.
	Ref string `json:"ref"`
	// Digest is the digest of the pushed artifact.
	Digest string `json:"digest,omitempty"`
	// Tags are the tags applied to the artifact.
	Tags []string `json:"tags,omitempty"`
	// Repository is the destination repository.
	Repository string `json:"repository"`
	// Files is the number of files synced.
	Files int `json:"files"`
	// Size is the total size in bytes of the pushed artifact.
	Size int64 `json:"size"`
	// SourceURL is the upstream URL of the revision.
	SourceURL string `json:"source_url,omitempty"`
	// Skipped is true when the revision was already synced and nothing was pushed.
	Skipped bool `json:"skipped"`
}

// Job syncs one model revision into the local registry.
type Job struct {
	// newRegistry creates the client of the local registry, overridable in tests.
	newRegistry func() packer.Registry
}

// MaxFails ...
func (j *Job) MaxFails() uint {
	return 1
}

// MaxCurrency ...
func (j *Job) MaxCurrency() uint {
	return 0
}

// ShouldRetry ...
func (j *Job) ShouldRetry() bool {
	return false
}

// Validate ...
func (j *Job) Validate(params job.Parameters) error {
	_, err := parseParams(params)
	return err
}

// Run ...
func (j *Job) Run(ctx job.Context, params job.Parameters) error {
	logger := ctx.GetLogger()
	p, err := parseParams(params)
	if err != nil {
		logger.Errorf("invalid parameters: %v", err)
		return err
	}

	stop := func() bool {
		cmd, exist := ctx.OPCommand()
		return exist && cmd == job.StopCommand
	}

	src, err := adapter.Create(p.Registry)
	if err != nil {
		logger.Errorf("failed to create model adapter for registry %s (%s): %v", p.Registry.Name, p.Registry.Type, err)
		return err
	}

	sysCtx := ctx.SystemContext()
	logger.Infof("resolving %s@%s from %s (%s)", p.SrcRepository, orDefault(p.SrcRevision), p.Registry.Name, p.Registry.URL)
	rev, err := src.ResolveModel(sysCtx, adapter.ModelRef{Repository: p.SrcRepository, Revision: p.SrcRevision})
	if err != nil {
		logger.Errorf("failed to resolve model: %v", err)
		return err
	}
	logger.Infof("resolved to revision %s with %d files (%s)", rev.ID, len(rev.Files), rev.SourceURL)

	files := filter.Apply(p.FileFilters, rev.Files)
	if len(p.FileFilters) > 0 {
		logger.Infof("%d of %d files match filters %v", len(files), len(rev.Files), p.FileFilters)
	}

	local := j.registry()

	// revision cursor check: no-op when the cursor matches and the destination artifact exists
	tag := packer.RevisionTag(rev.ID)
	if p.LastSyncedRevision == rev.ID {
		exist, desc, err := local.ManifestExist(p.DestRepository, tag)
		if err != nil {
			logger.Warningf("failed to check existence of %s:%s, continue syncing: %v", p.DestRepository, tag, err)
		} else if exist {
			logger.Infof("revision %s is already synced as %s:%s (%s), skip", rev.ID, p.DestRepository, tag, desc.Digest)
			return j.report(ctx, &Result{
				Revision: rev.ID, Ref: rev.Ref, Digest: desc.Digest.String(), Tags: []string{tag},
				Repository: p.DestRepository, Files: len(files), SourceURL: rev.SourceURL, Skipped: true,
			})
		} else {
			logger.Infof("cursor matches revision %s but %s:%s is missing, re-syncing", rev.ID, p.DestRepository, tag)
		}
	}

	if stop() {
		logger.Infof("job stopped before syncing")
		return nil
	}

	res, err := packer.New(local).Pack(sysCtx, src, rev, files, packer.Options{
		Repository:       p.DestRepository,
		Adapter:          p.Registry.Type,
		SourceRepository: p.SrcRepository,
		Logger:           logger,
		Stop:             stop,
	})
	if err != nil {
		if err == packer.ErrStopped {
			logger.Infof("job stopped")
			return nil
		}
		logger.Errorf("failed to pack model: %v", err)
		return err
	}
	logger.Infof("synced %s@%s to %s (%s) with tags %v", p.SrcRepository, rev.ID, p.DestRepository, res.Digest, res.Tags)

	return j.report(ctx, &Result{
		Revision: rev.ID, Ref: rev.Ref, Digest: res.Digest, Tags: res.Tags,
		Repository: p.DestRepository, Files: len(res.Manifest.Layers), Size: res.Size, SourceURL: rev.SourceURL,
	})
}

func (j *Job) report(ctx job.Context, result *Result) error {
	data, err := json.Marshal(result)
	if err != nil {
		return err
	}
	if err := ctx.Checkin(string(data)); err != nil {
		ctx.GetLogger().Errorf("failed to check in the result: %v", err)
		return err
	}
	return nil
}

func (j *Job) registry() packer.Registry {
	if j.newRegistry != nil {
		return j.newRegistry()
	}
	return newLocalRegistry()
}

// newLocalRegistry creates a client of the local Harbor registry going through
// core with the jobservice secret, so quota, events and webhooks all apply.
func newLocalRegistry() packer.Registry {
	return registry.NewClientWithAuthorizer(
		config.InternalCoreURL(),
		auth.NewSecretAuthorizer(config.JobserviceSecret()),
		!commonhttp.InternalTLSEnabled(),
		"",
	)
}

func parseParams(params job.Parameters) (*Params, error) {
	p := &Params{}
	regStr, err := stringParam(params, ParamRegistry, true)
	if err != nil {
		return nil, err
	}
	p.Registry = &regmodel.Registry{}
	if err := json.Unmarshal([]byte(regStr), p.Registry); err != nil {
		return nil, errors.BadRequestError(err).WithMessagef("invalid %s", ParamRegistry)
	}
	if p.Registry.Type == "" {
		return nil, errors.BadRequestError(nil).WithMessagef("registry type is required")
	}
	if !adapter.HasFactory(p.Registry.Type) {
		return nil, errors.BadRequestError(nil).WithMessagef("no model adapter for registry type %s", p.Registry.Type)
	}
	if p.SrcRepository, err = stringParam(params, ParamSrcRepository, true); err != nil {
		return nil, err
	}
	if p.SrcRevision, err = stringParam(params, ParamSrcRevision, false); err != nil {
		return nil, err
	}
	if p.DestRepository, err = stringParam(params, ParamDestRepository, true); err != nil {
		return nil, err
	}
	if p.LastSyncedRevision, err = stringParam(params, ParamLastSyncedRevision, false); err != nil {
		return nil, err
	}
	filtersStr, err := stringParam(params, ParamFileFilters, false)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(filtersStr) != "" {
		if err := json.Unmarshal([]byte(filtersStr), &p.FileFilters); err != nil {
			return nil, errors.BadRequestError(err).WithMessagef("invalid %s", ParamFileFilters)
		}
		if err := filter.Validate(p.FileFilters); err != nil {
			return nil, errors.BadRequestError(err)
		}
	}
	return p, nil
}

func stringParam(params job.Parameters, name string, required bool) (string, error) {
	v, exist := params[name]
	if !exist || v == nil {
		if required {
			return "", errors.BadRequestError(nil).WithMessagef("param %s is required", name)
		}
		return "", nil
	}
	s, ok := v.(string)
	if !ok {
		return "", errors.BadRequestError(nil).WithMessagef("param %s must be a string", name)
	}
	if required && strings.TrimSpace(s) == "" {
		return "", errors.BadRequestError(nil).WithMessagef("param %s is required", name)
	}
	return s, nil
}

func orDefault(rev string) string {
	if rev == "" {
		return "<default>"
	}
	return rev
}

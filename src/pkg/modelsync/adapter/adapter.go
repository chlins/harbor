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

// Package adapter defines the Model Adapter contract of the model sync framework.
//
// The contract is deliberately narrow: resolve and stream. Everything OCI (layout,
// digests, manifests, pushing) is owned by the framework, so adapters never need
// to fake registry semantics. Adapters are implemented once per model hub and
// registered through a Factory, following the same registration pattern as
// replication adapters and preheat providers.
package adapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/goharbor/harbor/src/pkg/reg/model"
)

// ModelRef identifies a model in an upstream hub.
type ModelRef struct {
	// Repository is the hub-side identifier, e.g. "Qwen/Qwen3-8B".
	Repository string
	// Revision is a branch, tag, or immutable revision ID; empty means the default branch.
	Revision string
}

// File describes one file of a resolved model revision.
type File struct {
	Path string
	Size int64
	// SHA256 is the content digest when the hub provides one (e.g. Git LFS objects); empty otherwise.
	SHA256 string
}

// Revision is an immutable snapshot of a model.
type Revision struct {
	// Ref is the ref as requested.
	Ref string
	// ID is the immutable revision identifier (e.g. a git commit SHA).
	ID string
	// Files lists the files of the revision.
	Files []File
	// Metadata carries model card fields: license, pipeline tag, library, ...
	Metadata map[string]string
	// SourceURL is the human-facing URL of the model at the hub, used for provenance.
	SourceURL string
}

// Well-known metadata keys populated by adapters.
const (
	MetadataLicense      = "license"
	MetadataPipelineTag  = "pipeline_tag"
	MetadataLibrary      = "library"
	MetadataAuthor       = "author"
	MetadataTags         = "tags"
	MetadataDescription  = "description"
	MetadataLastModified = "last_modified"
)

// Info describes the adapter metadata and capabilities.
type Info struct {
	// Type is the registry type the adapter serves, e.g. "huggingface".
	Type string
	// Description is a human readable description.
	Description string
	// DefaultRevision is the revision used when none is specified, e.g. "main".
	DefaultRevision string
}

// Adapter is implemented once per model hub.
type Adapter interface {
	// Info returns the adapter metadata and capabilities.
	Info(ctx context.Context) (*Info, error)
	// HealthCheck verifies endpoint reachability and credential validity.
	HealthCheck(ctx context.Context) error
	// ResolveModel resolves ref to an immutable revision snapshot.
	ResolveModel(ctx context.Context, ref ModelRef) (*Revision, error)
	// FetchFile opens a streaming reader for one file at the resolved revision,
	// starting at offset to support resumption.
	FetchFile(ctx context.Context, rev *Revision, path string, offset int64) (io.ReadCloser, error)
}

// Factory creates an Adapter for a registry (the source endpoint and credential).
type Factory interface {
	Create(registry *model.Registry) (Adapter, error)
}

// FactoryFunc adapts a function to the Factory interface.
type FactoryFunc func(registry *model.Registry) (Adapter, error)

// Create ...
func (f FactoryFunc) Create(registry *model.Registry) (Adapter, error) {
	return f(registry)
}

var (
	factoriesMu sync.RWMutex
	factories   = map[string]Factory{}
)

// ErrNotFound is returned when no factory is registered for a registry type.
var ErrNotFound = errors.New("model adapter factory not found")

// RegisterFactory registers a factory for the given registry type.
func RegisterFactory(registryType string, factory Factory) error {
	if len(registryType) == 0 {
		return errors.New("invalid registry type")
	}
	if factory == nil {
		return errors.New("empty model adapter factory")
	}
	factoriesMu.Lock()
	defer factoriesMu.Unlock()
	if _, exist := factories[registryType]; exist {
		return fmt.Errorf("model adapter factory for %s already exists", registryType)
	}
	factories[registryType] = factory
	return nil
}

// GetFactory returns the factory registered for the registry type.
func GetFactory(registryType string) (Factory, error) {
	factoriesMu.RLock()
	defer factoriesMu.RUnlock()
	factory, exist := factories[registryType]
	if !exist {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, registryType)
	}
	return factory, nil
}

// HasFactory returns whether a factory is registered for the registry type.
func HasFactory(registryType string) bool {
	_, err := GetFactory(registryType)
	return err == nil
}

// ListRegisteredTypes returns the sorted registry types that have a model adapter.
func ListRegisteredTypes() []string {
	factoriesMu.RLock()
	defer factoriesMu.RUnlock()
	types := make([]string, 0, len(factories))
	for t := range factories {
		types = append(types, t)
	}
	sort.Strings(types)
	return types
}

// Create creates the adapter for the registry using the registered factory.
func Create(registry *model.Registry) (Adapter, error) {
	if registry == nil {
		return nil, errors.New("nil registry")
	}
	factory, err := GetFactory(registry.Type)
	if err != nil {
		return nil, err
	}
	return factory.Create(registry)
}

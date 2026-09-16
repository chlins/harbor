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

package job

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/docker/distribution"
	"github.com/opencontainers/go-digest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/jobservice/job"
	"github.com/goharbor/harbor/src/pkg/modelsync/packer"
	regmodel "github.com/goharbor/harbor/src/pkg/reg/model"
	"github.com/goharbor/harbor/src/testing/jobservice"
)

const sha = "71034c5d8bde858ff824298bdedc65515b97d2b9"

// memRegistry is a minimal in-memory registry.
type memRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	uploads   map[string]*bytes.Buffer
	manifests map[string][]byte
	seq       int
}

func newMemRegistry() *memRegistry {
	return &memRegistry{blobs: map[string][]byte{}, uploads: map[string]*bytes.Buffer{}, manifests: map[string][]byte{}}
}

func (r *memRegistry) BlobExist(_, dgst string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.blobs[dgst]
	return ok, nil
}

func (r *memRegistry) PushBlob(_, dgst string, _ int64, blob io.Reader) error {
	data, _ := io.ReadAll(blob)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blobs[dgst] = data
	return nil
}

func (r *memRegistry) PushBlobChunk(_, dgst string, blobSize int64, chunk io.Reader, start, end int64, location string) (string, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if start == 0 {
		r.seq++
		location = fmt.Sprintf("u%d", r.seq)
		r.uploads[location] = &bytes.Buffer{}
	}
	buf := r.uploads[location]
	if _, err := io.Copy(buf, chunk); err != nil {
		return "", 0, err
	}
	if end == blobSize-1 {
		r.blobs[dgst] = append([]byte{}, buf.Bytes()...)
		delete(r.uploads, location)
	}
	return location, end, nil
}

func (r *memRegistry) ManifestExist(repo, ref string) (bool, *distribution.Descriptor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.manifests[repo+":"+ref]
	if !ok {
		return false, nil, nil
	}
	return true, &distribution.Descriptor{Digest: digest.FromBytes(p)}, nil
}

func (r *memRegistry) PushManifest(repo, ref, _ string, payload []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[repo+":"+ref] = payload
	return digest.FromBytes(payload).String(), nil
}

func newHub(t *testing.T) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models/org/model/revision/main", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "org/model", "sha": sha, "cardData": map[string]any{"license": "mit"}})
	})
	mux.HandleFunc("/api/models/org/model/tree/"+sha, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"type":"file","path":"config.json","size":7,"oid":"x"},{"type":"file","path":"README.md","size":5,"oid":"y"},{"type":"file","path":"model.safetensors","size":3,"oid":"z"}]`)
	})
	mux.HandleFunc("/org/model/resolve/"+sha+"/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path[len("/org/model/resolve/"+sha+"/"):] {
		case "config.json":
			fmt.Fprint(w, `{"a":1}`)
		case "README.md":
			fmt.Fprint(w, "hello")
		case "model.safetensors":
			fmt.Fprint(w, "abc")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func params(t *testing.T, hubURL string, filters []string, cursor string) job.Parameters {
	p := &Params{
		Registry:           &regmodel.Registry{ID: 1, Name: "hf", Type: regmodel.RegistryTypeHuggingFace, URL: hubURL},
		SrcRepository:      "org/model",
		FileFilters:        filters,
		DestRepository:     "library/org/model",
		LastSyncedRevision: cursor,
	}
	jp, err := p.ToJobParameters()
	require.NoError(t, err)
	return jp
}

func newCtx() *jobservice.MockJobContext {
	ctx := &jobservice.MockJobContext{}
	ctx.On("OPCommand").Return(job.NilCommand, false)
	return ctx
}

func TestValidate(t *testing.T) {
	j := &Job{}
	assert.NoError(t, j.Validate(params(t, "http://x", []string{"*.json"}, "")))
	assert.Error(t, j.Validate(job.Parameters{}))
	assert.Error(t, j.Validate(job.Parameters{ParamRegistry: "not-json", ParamSrcRepository: "a/b", ParamDestRepository: "c/d"}))
	assert.Error(t, j.Validate(job.Parameters{ParamRegistry: `{"type":"docker-hub"}`, ParamSrcRepository: "a/b", ParamDestRepository: "c/d"}))
	assert.Error(t, j.Validate(job.Parameters{ParamRegistry: `{"type":"huggingface"}`, ParamSrcRepository: "a/b", ParamDestRepository: "c/d", ParamFileFilters: `["["]`}))
	assert.Error(t, j.Validate(job.Parameters{ParamRegistry: `{"type":"huggingface"}`, ParamSrcRepository: 1, ParamDestRepository: "c/d"}))
	assert.Equal(t, uint(1), j.MaxFails())
	assert.Equal(t, uint(0), j.MaxCurrency())
	assert.False(t, j.ShouldRetry())
}

func TestRun(t *testing.T) {
	hub := newHub(t)
	reg := newMemRegistry()
	j := &Job{newRegistry: func() packer.Registry { return reg }}

	var checkin string
	ctx := newCtx()
	ctx.On("Checkin", mock.Anything).Run(func(args mock.Arguments) { checkin = args.String(0) }).Return(nil)

	require.NoError(t, j.Run(ctx, params(t, hub.URL, []string{"*.json", "README.md"}, "")))
	res := &Result{}
	require.NoError(t, json.Unmarshal([]byte(checkin), res))
	assert.Equal(t, sha, res.Revision)
	assert.Equal(t, "main", res.Ref)
	assert.Equal(t, 2, res.Files, "safetensors filtered out")
	assert.False(t, res.Skipped)
	assert.Equal(t, []string{"sha-71034c5d8bde", "main"}, res.Tags)
	exist, desc, _ := reg.ManifestExist("library/org/model", "sha-71034c5d8bde")
	assert.True(t, exist)
	assert.Equal(t, res.Digest, desc.Digest.String())

	// second run with the cursor set: skipped
	checkin = ""
	require.NoError(t, j.Run(ctx, params(t, hub.URL, nil, sha)))
	require.NoError(t, json.Unmarshal([]byte(checkin), res))
	assert.True(t, res.Skipped)
	assert.Equal(t, sha, res.Revision)

	// cursor set but artifact missing in a fresh registry: re-synced
	reg2 := newMemRegistry()
	j2 := &Job{newRegistry: func() packer.Registry { return reg2 }}
	checkin = ""
	require.NoError(t, j2.Run(ctx, params(t, hub.URL, nil, sha)))
	require.NoError(t, json.Unmarshal([]byte(checkin), res))
	assert.False(t, res.Skipped)
	assert.Equal(t, 3, res.Files)
}

func TestRunErrors(t *testing.T) {
	hub := newHub(t)
	j := &Job{newRegistry: func() packer.Registry { return newMemRegistry() }}
	ctx := newCtx()

	assert.Error(t, j.Run(ctx, job.Parameters{}))

	// resolve failure
	p := params(t, hub.URL, nil, "")
	p[ParamSrcRepository] = "org/missing"
	assert.Error(t, j.Run(ctx, p))

	// stopped before packing
	stopCtx := &jobservice.MockJobContext{}
	stopCtx.On("OPCommand").Return(job.StopCommand, true)
	assert.NoError(t, j.Run(stopCtx, params(t, hub.URL, nil, "")))
}

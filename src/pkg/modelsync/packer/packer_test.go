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

package packer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/docker/distribution"
	modelspec "github.com/modelpack/model-spec/specs-go/v1"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/pkg/modelsync/adapter"
)

// fakeRegistry is an in-memory registry implementing the chunked upload protocol.
type fakeRegistry struct {
	mu        sync.Mutex
	blobs     map[string][]byte
	uploads   map[string]*bytes.Buffer
	manifests map[string][]byte // repo:ref -> payload
	seq       int
	pushes    int
}

func newFakeRegistry() *fakeRegistry {
	return &fakeRegistry{blobs: map[string][]byte{}, uploads: map[string]*bytes.Buffer{}, manifests: map[string][]byte{}}
}

func (r *fakeRegistry) BlobExist(_, dgst string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.blobs[dgst]
	return ok, nil
}

func (r *fakeRegistry) PushBlob(_, dgst string, size int64, blob io.Reader) error {
	data, err := io.ReadAll(blob)
	if err != nil {
		return err
	}
	if int64(len(data)) != size || digest.FromBytes(data).String() != dgst {
		return fmt.Errorf("digest/size mismatch")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blobs[dgst] = data
	r.pushes++
	return nil
}

func (r *fakeRegistry) PushBlobChunk(_, dgst string, blobSize int64, chunk io.Reader, start, end int64, location string) (string, int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if start == 0 {
		r.seq++
		location = fmt.Sprintf("upload-%d", r.seq)
		r.uploads[location] = &bytes.Buffer{}
	}
	buf, ok := r.uploads[location]
	if !ok {
		return "", 0, fmt.Errorf("unknown upload %s", location)
	}
	if int64(buf.Len()) != start {
		return "", 0, fmt.Errorf("bad range: have %d, start %d", buf.Len(), start)
	}
	n, err := io.Copy(buf, chunk)
	if err != nil {
		return "", 0, err
	}
	if start+n-1 != end {
		return "", 0, fmt.Errorf("bad end: %d vs %d", start+n-1, end)
	}
	if end == blobSize-1 {
		data := buf.Bytes()
		if digest.FromBytes(data).String() != dgst {
			return "", 0, fmt.Errorf("digest mismatch on final chunk")
		}
		r.blobs[dgst] = append([]byte{}, data...)
		delete(r.uploads, location)
		r.pushes++
	}
	return location, end, nil
}

func (r *fakeRegistry) ManifestExist(repo, ref string) (bool, *distribution.Descriptor, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	payload, ok := r.manifests[repo+":"+ref]
	if !ok {
		return false, nil, nil
	}
	return true, &distribution.Descriptor{Digest: digest.FromBytes(payload), Size: int64(len(payload))}, nil
}

func (r *fakeRegistry) PushManifest(repo, ref, _ string, payload []byte) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.manifests[repo+":"+ref] = payload
	return digest.FromBytes(payload).String(), nil
}

// fakeHub serves files from memory.
type fakeHub struct {
	files   map[string][]byte
	fetches int
	failN   int // fail the first N fetches
}

func (h *fakeHub) Info(context.Context) (*adapter.Info, error) {
	return &adapter.Info{Type: "fake"}, nil
}
func (h *fakeHub) HealthCheck(context.Context) error { return nil }
func (h *fakeHub) ResolveModel(context.Context, adapter.ModelRef) (*adapter.Revision, error) {
	return nil, nil
}
func (h *fakeHub) FetchFile(_ context.Context, _ *adapter.Revision, path string, offset int64) (io.ReadCloser, error) {
	h.fetches++
	if h.failN > 0 {
		h.failN--
		return nil, fmt.Errorf("transient")
	}
	data, ok := h.files[path]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return io.NopCloser(bytes.NewReader(data[offset:])), nil
}

func sha(data []byte) string {
	s := sha256.Sum256(data)
	return fmt.Sprintf("%x", s)
}

func fixture() (*fakeHub, *adapter.Revision, []adapter.File) {
	weights := bytes.Repeat([]byte("w"), 25) // 3 chunks with ChunkSize 10
	config := []byte(`{"model_type":"gpt2"}`)
	readme := []byte("# model")
	hub := &fakeHub{files: map[string][]byte{
		"model.safetensors": weights,
		"config.json":       config,
		"README.md":         readme,
		".gitattributes":    []byte("x"),
	}}
	rev := &adapter.Revision{
		Ref: "main", ID: "71034c5d8bde858ff824298bdedc65515b97d2b9",
		SourceURL: "https://huggingface.co/org/model/tree/71034c5d8bde858ff824298bdedc65515b97d2b9",
		Metadata:  map[string]string{adapter.MetadataLicense: "apache-2.0", adapter.MetadataAuthor: "org", adapter.MetadataLibrary: "transformers"},
	}
	files := []adapter.File{
		{Path: "model.safetensors", Size: int64(len(weights)), SHA256: sha(weights)},
		{Path: "config.json", Size: int64(len(config))},
		{Path: "README.md", Size: int64(len(readme))},
		{Path: ".gitattributes", Size: 1},
	}
	return hub, rev, files
}

func opts(repo string) Options {
	return Options{Repository: repo, Adapter: "huggingface", SourceRepository: "org/model", ChunkSize: 10}
}

func TestPackDeterministic(t *testing.T) {
	ctx := context.Background()
	hub, rev, files := fixture()

	reg1 := newFakeRegistry()
	res1, err := New(reg1).Pack(ctx, hub, rev, files, opts("library/org/model"))
	require.NoError(t, err)

	// shuffle the input order and pack into a fresh registry
	shuffled := []adapter.File{files[2], files[0], files[3], files[1]}
	reg2 := newFakeRegistry()
	res2, err := New(reg2).Pack(ctx, hub, rev, shuffled, opts("other/repo"))
	require.NoError(t, err)

	assert.Equal(t, res1.Digest, res2.Digest, "same revision must produce a bit-identical digest")
	assert.Equal(t, []string{"sha-71034c5d8bde", "main"}, res1.Tags)

	// manifest content
	m := res1.Manifest
	assert.Equal(t, modelspec.ArtifactTypeModelManifest, m.ArtifactType)
	assert.Equal(t, modelspec.MediaTypeModelConfig, m.Config.MediaType)
	require.Len(t, m.Layers, 3, ".gitattributes must be skipped")
	assert.Equal(t, "README.md", m.Layers[0].Annotations[modelspec.AnnotationFilepath])
	assert.Equal(t, modelspec.MediaTypeModelDocRaw, m.Layers[0].MediaType)
	assert.Equal(t, "config.json", m.Layers[1].Annotations[modelspec.AnnotationFilepath])
	assert.Equal(t, modelspec.MediaTypeModelWeightConfigRaw, m.Layers[1].MediaType)
	assert.Equal(t, "model.safetensors", m.Layers[2].Annotations[modelspec.AnnotationFilepath])
	assert.Equal(t, modelspec.MediaTypeModelWeightRaw, m.Layers[2].MediaType)
	assert.Equal(t, "sha256:"+files[0].SHA256, m.Layers[2].Digest.String())
	assert.Equal(t, rev.SourceURL, m.Annotations[AnnotationSourceURL])
	assert.Equal(t, rev.ID, m.Annotations[AnnotationRevision])
	assert.Equal(t, "huggingface", m.Annotations[AnnotationAdapter])
	assert.Equal(t, "apache-2.0", m.Annotations[ocispec.AnnotationLicenses])

	// all blobs present and correct in registry
	for _, l := range m.Layers {
		data, ok := reg1.blobs[l.Digest.String()]
		require.True(t, ok, l.Annotations[modelspec.AnnotationFilepath])
		assert.Equal(t, hub.files[l.Annotations[modelspec.AnnotationFilepath]], data)
	}
	configData, ok := reg1.blobs[m.Config.Digest.String()]
	require.True(t, ok)
	cfg := modelspec.Model{}
	require.NoError(t, json.Unmarshal(configData, &cfg))
	assert.Equal(t, "layers", cfg.ModelFS.Type)
	assert.Len(t, cfg.ModelFS.DiffIDs, 3)
	assert.Equal(t, []string{"apache-2.0"}, cfg.Descriptor.Licenses)
	assert.Equal(t, rev.ID, cfg.Descriptor.Revision)
	assert.Nil(t, cfg.Descriptor.CreatedAt, "no timestamps for determinism")
	assert.Equal(t, "transformers", cfg.Config.Format)

	// manifests tagged
	for _, tag := range res1.Tags {
		exist, desc, err := reg1.ManifestExist("library/org/model", tag)
		require.NoError(t, err)
		assert.True(t, exist)
		assert.Equal(t, res1.Digest, desc.Digest.String())
	}
}

func TestPackReusesExistingBlobAndRetries(t *testing.T) {
	ctx := context.Background()
	hub, rev, files := fixture()
	reg := newFakeRegistry()
	weights := hub.files["model.safetensors"]
	reg.blobs["sha256:"+sha(weights)] = weights

	hub.failN = 2 // first two fetches fail, retry must succeed
	res, err := New(reg).Pack(ctx, hub, rev, files, opts("r"))
	require.NoError(t, err)
	assert.NotEmpty(t, res.Digest)
	// weights were never fetched again, only config and README were streamed (+2 failures)
	assert.Equal(t, 4, hub.fetches)
}

func TestPackErrors(t *testing.T) {
	ctx := context.Background()
	hub, rev, files := fixture()
	p := New(newFakeRegistry())

	_, err := p.Pack(ctx, hub, rev, files, Options{})
	assert.Error(t, err)
	_, err = p.Pack(ctx, hub, nil, files, opts("r"))
	assert.Error(t, err)
	_, err = p.Pack(ctx, hub, rev, []adapter.File{{Path: ".gitattributes"}}, opts("r"))
	assert.Error(t, err)

	// digest mismatch with hub-provided sha
	bad := []adapter.File{{Path: "config.json", Size: 21, SHA256: strings.Repeat("0", 64)}}
	_, err = p.Pack(ctx, hub, rev, bad, opts("r"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sha256 mismatch")

	// stop
	o := opts("r")
	o.Stop = func() bool { return true }
	_, err = p.Pack(ctx, hub, rev, files, o)
	assert.ErrorIs(t, err, ErrStopped)

	// fetch failure exhausts retries
	hub.failN = 100
	_, err = p.Pack(ctx, hub, rev, files, opts("r"))
	assert.Error(t, err)
}

func TestTags(t *testing.T) {
	rev := &adapter.Revision{Ref: "refs/pr/1", ID: "abcdef1234567890"}
	assert.Equal(t, []string{"sha-abcdef123456", "refs-pr-1", "latest"}, Tags(rev, "latest", "latest", ""))
	rev = &adapter.Revision{Ref: "71034c5d8bde858ff824298bdedc65515b97d2b9", ID: "71034c5d8bde858ff824298bdedc65515b97d2b9"}
	assert.Equal(t, []string{"sha-71034c5d8bde"}, Tags(rev))
	assert.Equal(t, "v1.0", SanitizeTag("-v1.0"))
}

func TestInferFileType(t *testing.T) {
	cases := map[string]FileType{
		"model.safetensors":       FileTypeWeight,
		"pytorch_model-00001.bin": FileTypeWeight,
		"onnx/model.onnx":         FileTypeWeight,
		"config.json":             FileTypeConfig,
		"tokenizer.model":         FileTypeConfig,
		"generation_config.json":  FileTypeConfig,
		"README.md":               FileTypeDoc,
		"LICENSE":                 FileTypeDoc,
		"modeling_custom.py":      FileTypeCode,
		"unknown.zzz":             FileTypeCode,
	}
	for name, want := range cases {
		assert.Equal(t, want, InferFileType(name, 1), name)
	}
	assert.Equal(t, FileTypeWeight, InferFileType("unknown.zzz", weightFileSizeThreshold+1))
	assert.Equal(t, modelspec.MediaTypeModelWeightRaw, FileTypeWeight.MediaType())
	assert.Equal(t, modelspec.MediaTypeModelWeightConfigRaw, FileTypeConfig.MediaType())
	assert.Equal(t, modelspec.MediaTypeModelCodeRaw, FileTypeCode.MediaType())
	assert.Equal(t, modelspec.MediaTypeModelDocRaw, FileTypeDoc.MediaType())
	assert.Equal(t, "weight", FileTypeWeight.String())
	assert.True(t, IsIgnored(".gitattributes"))
	assert.True(t, IsIgnored("sub/.gitignore"))
	assert.False(t, IsIgnored("sub/model.bin"))
}

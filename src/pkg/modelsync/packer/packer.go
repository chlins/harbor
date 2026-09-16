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

// Package packer assembles the files of a resolved model revision into a
// ModelPack model-spec OCI artifact deterministically and pushes it to a registry.
//
// Determinism rules:
//  1. files are ordered lexicographically by path;
//  2. each file becomes one raw-bytes layer (no tar, no compression) typed by
//     its model-spec file class;
//  3. the model-spec config is serialized canonically (sorted keys, no timestamps);
//  4. the manifest is assembled with a stable field order.
//
// Consequently, the same upstream revision with the same file filters always
// produces a bit-identical artifact digest.
package packer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/docker/distribution"
	modelspec "github.com/modelpack/model-spec/specs-go/v1"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/goharbor/harbor/src/pkg/modelsync/adapter"
)

const (
	// AnnotationSourceURL records the upstream URL of the model.
	AnnotationSourceURL = "io.goharbor.model-sync.source-url"
	// AnnotationRevision records the upstream immutable revision.
	AnnotationRevision = "io.goharbor.model-sync.revision"
	// AnnotationAdapter records the adapter (registry type) that produced the artifact.
	AnnotationAdapter = "io.goharbor.model-sync.adapter"
	// AnnotationRepository records the upstream repository.
	AnnotationRepository = "io.goharbor.model-sync.repository"

	// RevisionTagPrefix is the prefix of the immutable revision tag.
	RevisionTagPrefix = "sha-"
	// revisionTagLength is the number of revision characters kept in the immutable tag.
	revisionTagLength = 12

	// defaultChunkSize is the size of a blob upload chunk.
	defaultChunkSize = 10 * 1024 * 1024
	// defaultRetry is how many times a failed file upload is retried.
	defaultRetry = 3
)

var (
	tagInvalidChars = regexp.MustCompile(`[^A-Za-z0-9._-]`)
	commitSHARegexp = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// Registry is the subset of the registry client used by the packer.
type Registry interface {
	BlobExist(repository, digest string) (exist bool, err error)
	PushBlobChunk(repository, digest string, blobSize int64, chunk io.Reader, start, end int64, location string) (nextUploadLocation string, endRange int64, err error)
	PushBlob(repository, digest string, size int64, blob io.Reader) error
	ManifestExist(repository, reference string) (exist bool, desc *distribution.Descriptor, err error)
	PushManifest(repository, reference, mediaType string, payload []byte) (string, error)
}

// Logger is the subset of the job logger used by the packer.
type Logger interface {
	Infof(format string, v ...any)
	Warningf(format string, v ...any)
}

type nopLogger struct{}

func (nopLogger) Infof(string, ...any)    {}
func (nopLogger) Warningf(string, ...any) {}

// Options controls one packing run.
type Options struct {
	// Repository is the destination repository, e.g. "library/qwen/qwen3-8b".
	Repository string
	// Adapter is the registry type of the source hub, recorded as provenance.
	Adapter string
	// SourceRepository is the hub-side repository, recorded as provenance.
	SourceRepository string
	// ExtraTags are applied to the artifact in addition to the revision tag
	// and the branch tag (if any).
	ExtraTags []string
	// Logger receives progress messages.
	Logger Logger
	// ChunkSize overrides the upload chunk size (for tests).
	ChunkSize int64
	// Stop is polled between files; when it returns true the run is aborted.
	Stop func() bool
}

// Result describes the pushed artifact.
type Result struct {
	Digest   string
	Size     int64
	Tags     []string
	Manifest *ocispec.Manifest
	// Skipped is true when the artifact already existed in the destination.
	Skipped bool
}

// Packer packs model revisions into model-spec artifacts.
type Packer struct {
	registry Registry
}

// New creates a packer pushing to the registry.
func New(registry Registry) *Packer {
	return &Packer{registry: registry}
}

// ErrStopped is returned when the run is aborted by the Stop callback.
var ErrStopped = fmt.Errorf("model sync stopped")

// Tags returns the tags applied to a revision: the immutable "sha-<12>" tag and,
// when the requested ref is a branch or tag rather than a commit, the sanitized ref.
func Tags(rev *adapter.Revision, extra ...string) []string {
	tags := []string{RevisionTag(rev.ID)}
	if rev.Ref != "" && rev.Ref != rev.ID && !commitSHARegexp.MatchString(rev.Ref) {
		if t := SanitizeTag(rev.Ref); t != "" && t != tags[0] {
			tags = append(tags, t)
		}
	}
	for _, e := range extra {
		if t := SanitizeTag(e); t != "" {
			dup := false
			for _, existing := range tags {
				if existing == t {
					dup = true
					break
				}
			}
			if !dup {
				tags = append(tags, t)
			}
		}
	}
	return tags
}

// RevisionTag returns the immutable tag of the revision.
func RevisionTag(revisionID string) string {
	id := revisionID
	if len(id) > revisionTagLength {
		id = id[:revisionTagLength]
	}
	return RevisionTagPrefix + SanitizeTag(id)
}

// SanitizeTag turns an arbitrary ref into a valid OCI tag.
func SanitizeTag(ref string) string {
	t := tagInvalidChars.ReplaceAllString(strings.TrimSpace(ref), "-")
	t = strings.TrimLeft(t, ".-")
	if len(t) > 128 {
		t = t[:128]
	}
	return t
}

// Pack pushes the files of the revision as a model-spec artifact.
func (p *Packer) Pack(ctx context.Context, src adapter.Adapter, rev *adapter.Revision, files []adapter.File, opts Options) (*Result, error) {
	if opts.Logger == nil {
		opts.Logger = nopLogger{}
	}
	if opts.ChunkSize <= 0 {
		opts.ChunkSize = defaultChunkSize
	}
	if opts.Repository == "" {
		return nil, fmt.Errorf("destination repository is required")
	}
	if rev == nil || rev.ID == "" {
		return nil, fmt.Errorf("resolved revision is required")
	}

	// 1. order files lexicographically and drop hub bookkeeping files
	sorted := make([]adapter.File, 0, len(files))
	for _, f := range files {
		if IsIgnored(f.Path) {
			opts.Logger.Infof("skip hub metadata file %s", f.Path)
			continue
		}
		sorted = append(sorted, f)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	if len(sorted) == 0 {
		return nil, fmt.Errorf("no files to sync after applying filters")
	}

	// 2. one raw layer per file
	layers := make([]ocispec.Descriptor, 0, len(sorted))
	var total int64
	for i, f := range sorted {
		if opts.Stop != nil && opts.Stop() {
			return nil, ErrStopped
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ft := InferFileType(f.Path, f.Size)
		opts.Logger.Infof("[%d/%d] syncing %s (%s, %d bytes)", i+1, len(sorted), f.Path, ft, f.Size)
		desc, err := p.pushFile(ctx, src, rev, f, ft.MediaType(), opts)
		if err != nil {
			return nil, fmt.Errorf("failed to sync file %s: %w", f.Path, err)
		}
		layers = append(layers, desc)
		total += desc.Size
	}

	// 3. canonical config
	configJSON, err := BuildConfig(rev, layers, opts)
	if err != nil {
		return nil, err
	}
	configDesc := ocispec.Descriptor{
		MediaType: modelspec.MediaTypeModelConfig,
		Digest:    digest.FromBytes(configJSON),
		Size:      int64(len(configJSON)),
	}
	if err := p.pushBytes(opts.Repository, configDesc, configJSON); err != nil {
		return nil, fmt.Errorf("failed to push model config: %w", err)
	}

	// 4. stable manifest
	manifest := BuildManifest(rev, configDesc, layers, opts)
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	manifestDigest := digest.FromBytes(manifestJSON)
	tags := Tags(rev, opts.ExtraTags...)
	for _, tag := range tags {
		if _, err := p.registry.PushManifest(opts.Repository, tag, manifest.MediaType, manifestJSON); err != nil {
			return nil, fmt.Errorf("failed to push manifest with tag %s: %w", tag, err)
		}
		opts.Logger.Infof("pushed %s:%s (%s)", opts.Repository, tag, manifestDigest)
	}

	return &Result{
		Digest:   manifestDigest.String(),
		Size:     total + configDesc.Size + int64(len(manifestJSON)),
		Tags:     tags,
		Manifest: manifest,
	}, nil
}

// BuildConfig serializes the model-spec config canonically: no timestamps, and
// map keys sorted by encoding/json.
func BuildConfig(rev *adapter.Revision, layers []ocispec.Descriptor, opts Options) ([]byte, error) {
	diffIDs := make([]digest.Digest, 0, len(layers))
	for _, l := range layers {
		// raw layers are uncompressed so the diff id equals the layer digest
		diffIDs = append(diffIDs, l.Digest)
	}
	desc := modelspec.ModelDescriptor{
		Name:      opts.SourceRepository,
		SourceURL: rev.SourceURL,
		Revision:  rev.ID,
		Version:   rev.Ref,
	}
	if author := rev.Metadata[adapter.MetadataAuthor]; author != "" {
		desc.Vendor = author
		desc.Authors = []string{author}
	}
	if license := rev.Metadata[adapter.MetadataLicense]; license != "" {
		for l := range strings.SplitSeq(license, ",") {
			if l = strings.TrimSpace(l); l != "" {
				desc.Licenses = append(desc.Licenses, l)
			}
		}
	}
	if d := rev.Metadata[adapter.MetadataDescription]; d != "" {
		desc.Description = d
	}
	model := modelspec.Model{
		Descriptor: desc,
		ModelFS: modelspec.ModelFS{
			Type:    "layers",
			DiffIDs: diffIDs,
		},
	}
	if lib := rev.Metadata[adapter.MetadataLibrary]; lib != "" {
		model.Config.Format = lib
	}
	if arch := rev.Metadata[adapter.MetadataPipelineTag]; arch != "" {
		model.Config.Architecture = arch
	}
	return json.Marshal(model)
}

// BuildManifest assembles the manifest with a stable field order and the
// provenance annotations.
func BuildManifest(rev *adapter.Revision, config ocispec.Descriptor, layers []ocispec.Descriptor, opts Options) *ocispec.Manifest {
	annotations := map[string]string{
		AnnotationSourceURL: rev.SourceURL,
		AnnotationRevision:  rev.ID,
		AnnotationAdapter:   opts.Adapter,
	}
	if opts.SourceRepository != "" {
		annotations[AnnotationRepository] = opts.SourceRepository
	}
	if license := rev.Metadata[adapter.MetadataLicense]; license != "" {
		annotations[ocispec.AnnotationLicenses] = license
	}
	if rev.SourceURL != "" {
		annotations[ocispec.AnnotationSource] = rev.SourceURL
	}
	annotations[ocispec.AnnotationRevision] = rev.ID
	return &ocispec.Manifest{
		Versioned:    specs.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: modelspec.ArtifactTypeModelManifest,
		Config:       config,
		Layers:       layers,
		Annotations:  annotations,
	}
}

func (p *Packer) pushBytes(repository string, desc ocispec.Descriptor, data []byte) error {
	exist, err := p.registry.BlobExist(repository, desc.Digest.String())
	if err != nil {
		return err
	}
	if exist {
		return nil
	}
	return p.registry.PushBlob(repository, desc.Digest.String(), desc.Size, bytes.NewReader(data))
}

// pushFile streams one file from the hub into the registry as a raw layer.
// When the hub provides the sha256 the blob is skipped if it already exists;
// otherwise the digest is computed while streaming and the chunked upload API
// is used so nothing is materialized on local disk.
func (p *Packer) pushFile(ctx context.Context, src adapter.Adapter, rev *adapter.Revision, f adapter.File, mediaType string, opts Options) (ocispec.Descriptor, error) {
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Size:      f.Size,
		Annotations: map[string]string{
			modelspec.AnnotationFilepath: f.Path,
		},
	}
	if f.SHA256 != "" {
		dgst := digest.NewDigestFromEncoded(digest.SHA256, f.SHA256)
		if err := dgst.Validate(); err != nil {
			return desc, fmt.Errorf("invalid sha256 %q from hub: %w", f.SHA256, err)
		}
		exist, err := p.registry.BlobExist(opts.Repository, dgst.String())
		if err != nil {
			return desc, err
		}
		if exist {
			opts.Logger.Infof("blob %s of %s already exists, skipped", dgst, f.Path)
			desc.Digest = dgst
			return desc, nil
		}
	}

	var (
		dgst digest.Digest
		size int64
		err  error
	)
	for attempt := 1; attempt <= defaultRetry; attempt++ {
		dgst, size, err = p.streamFile(ctx, src, rev, f, opts)
		if err == nil {
			break
		}
		if ctx.Err() != nil || err == ErrStopped {
			return desc, err
		}
		opts.Logger.Warningf("attempt %d/%d to sync %s failed: %v", attempt, defaultRetry, f.Path, err)
	}
	if err != nil {
		return desc, err
	}
	if f.SHA256 != "" && dgst.Encoded() != f.SHA256 {
		return desc, fmt.Errorf("sha256 mismatch for %s: hub %s, streamed %s", f.Path, f.SHA256, dgst.Encoded())
	}
	if f.Size > 0 && size != f.Size {
		return desc, fmt.Errorf("size mismatch for %s: hub %d, streamed %d", f.Path, f.Size, size)
	}
	desc.Digest = dgst
	desc.Size = size
	return desc, nil
}

// streamFile uploads the file in chunks while hashing it. The final chunk is
// detected by reading ahead, so the digest is complete when the last PUT is sent.
func (p *Packer) streamFile(ctx context.Context, src adapter.Adapter, rev *adapter.Revision, f adapter.File, opts Options) (digest.Digest, int64, error) {
	rc, err := src.FetchFile(ctx, rev, f.Path, 0)
	if err != nil {
		return "", 0, err
	}
	defer rc.Close()

	hasher := sha256.New()
	// tentative digest; the real one is only known at the end, and the
	// registry only needs it on the final PUT
	var (
		location string
		start    int64
		buf      = make([]byte, opts.ChunkSize)
		next     []byte
		eof      bool
	)
	// prime the read-ahead
	n, rerr := io.ReadFull(rc, buf)
	next = buf[:n]
	if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
		eof = true
	} else if rerr != nil {
		return "", 0, rerr
	}
	if n == 0 && eof {
		return "", 0, fmt.Errorf("empty file %s is not supported", f.Path)
	}

	spare := make([]byte, opts.ChunkSize)
	for {
		if opts.Stop != nil && opts.Stop() {
			return "", 0, ErrStopped
		}
		chunk := next
		hasher.Write(chunk)

		var lookahead []byte
		if !eof {
			m, rerr := io.ReadFull(rc, spare)
			lookahead = spare[:m]
			if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
				eof = true
			} else if rerr != nil {
				return "", 0, rerr
			}
			if m == 0 {
				lookahead = nil
			}
		}
		last := eof && len(lookahead) == 0
		end := start + int64(len(chunk)) - 1

		dgst := ""
		blobSize := int64(-1)
		if last {
			dgst = digest.NewDigest(digest.SHA256, hasher).String()
			blobSize = end + 1
		}
		location, _, err = p.registry.PushBlobChunk(opts.Repository, dgst, blobSize, bytes.NewReader(chunk), start, end, location)
		if err != nil {
			return "", 0, err
		}
		start = end + 1
		if last {
			return digest.Digest(dgst), start, nil
		}
		// swap buffers
		buf, spare = spare, buf
		next = lookahead
	}
}

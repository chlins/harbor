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

// Package huggingface implements the model adapter for the Hugging Face hub.
package huggingface

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	common_http "github.com/goharbor/harbor/src/common/http"
	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/lib/log"
	"github.com/goharbor/harbor/src/pkg/modelsync/adapter"
	reghf "github.com/goharbor/harbor/src/pkg/reg/adapter/huggingface"
	"github.com/goharbor/harbor/src/pkg/reg/model"
)

const (
	// DefaultRevision is the default branch of Hugging Face repositories.
	DefaultRevision = "main"
	// treePageSize is the page size used when listing the file tree.
	treePageSize = 1000
	// resolveTimeout is the timeout used for Hub API requests. File streaming
	// requests have no overall timeout, since large weights can take a long time
	// to download; the context is used for cancellation instead.
	resolveTimeout = 2 * time.Minute
)

var (
	repoRegexp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)?$`)
	shaRegexp  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func init() {
	if err := adapter.RegisterFactory(model.RegistryTypeHuggingFace, adapter.FactoryFunc(func(r *model.Registry) (adapter.Adapter, error) {
		return New(r), nil
	})); err != nil {
		log.Errorf("failed to register model adapter factory for %s: %v", model.RegistryTypeHuggingFace, err)
	}
}

var _ adapter.Adapter = (*Adapter)(nil)

// Adapter is the Hugging Face model adapter.
type Adapter struct {
	registry *model.Registry
	endpoint string
	token    string
	// resolveClient is used for API calls with a timeout.
	resolveClient *http.Client
	// fetchClient is used for streaming file downloads without a timeout.
	fetchClient *http.Client
}

// New creates a Hugging Face model adapter for the registry.
func New(registry *model.Registry) *Adapter {
	transport := common_http.GetHTTPTransport(
		common_http.WithInsecure(registry.Insecure),
		common_http.WithCACert(registry.CACertificate),
	)
	return &Adapter{
		registry:      registry,
		endpoint:      reghf.Endpoint(registry),
		token:         reghf.Token(registry),
		resolveClient: &http.Client{Transport: transport, Timeout: resolveTimeout},
		fetchClient:   &http.Client{Transport: transport},
	}
}

// Info ...
func (a *Adapter) Info(_ context.Context) (*adapter.Info, error) {
	return &adapter.Info{
		Type:            model.RegistryTypeHuggingFace,
		Description:     "Hugging Face model hub",
		DefaultRevision: DefaultRevision,
	}, nil
}

// HealthCheck ...
func (a *Adapter) HealthCheck(ctx context.Context) error {
	status, err := reghf.New(a.registry).HealthCheck()
	if err != nil {
		return err
	}
	if status != model.Healthy {
		return fmt.Errorf("hugging face endpoint %s is unhealthy", a.endpoint)
	}
	_ = ctx
	return nil
}

// modelInfo is the subset of the Hub model API response used by the adapter.
type modelInfo struct {
	ID           string         `json:"id"`
	SHA          string         `json:"sha"`
	Author       string         `json:"author"`
	PipelineTag  string         `json:"pipeline_tag"`
	LibraryName  string         `json:"library_name"`
	Tags         []string       `json:"tags"`
	Gated        any            `json:"gated"`
	Private      bool           `json:"private"`
	LastModified string         `json:"lastModified"`
	CardData     map[string]any `json:"cardData"`
}

// treeEntry is one entry of the Hub tree API response.
type treeEntry struct {
	Type string `json:"type"`
	Path string `json:"path"`
	Size int64  `json:"size"`
	OID  string `json:"oid"`
	LFS  *struct {
		OID  string `json:"oid"`
		Size int64  `json:"size"`
	} `json:"lfs"`
}

// ResolveModel resolves the ref to an immutable revision snapshot.
func (a *Adapter) ResolveModel(ctx context.Context, ref adapter.ModelRef) (*adapter.Revision, error) {
	repo := strings.Trim(strings.TrimSpace(ref.Repository), "/")
	if !repoRegexp.MatchString(repo) {
		return nil, errors.BadRequestError(nil).WithMessagef("invalid hugging face repository: %q", ref.Repository)
	}
	rev := strings.TrimSpace(ref.Revision)
	if rev == "" {
		rev = DefaultRevision
	}

	info, err := a.getModelInfo(ctx, repo, rev)
	if err != nil {
		return nil, err
	}
	if info.SHA == "" {
		return nil, fmt.Errorf("hugging face returned no commit sha for %s@%s", repo, rev)
	}

	// list the tree at the immutable commit so the file list matches the sha
	files, err := a.listTree(ctx, repo, info.SHA)
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })

	return &adapter.Revision{
		Ref:       rev,
		ID:        info.SHA,
		Files:     files,
		Metadata:  buildMetadata(info),
		SourceURL: fmt.Sprintf("%s/%s/tree/%s", a.endpoint, repo, info.SHA),
	}, nil
}

func buildMetadata(info *modelInfo) map[string]string {
	md := map[string]string{}
	set := func(k, v string) {
		if v != "" {
			md[k] = v
		}
	}
	set(adapter.MetadataAuthor, info.Author)
	set(adapter.MetadataPipelineTag, info.PipelineTag)
	set(adapter.MetadataLibrary, info.LibraryName)
	set(adapter.MetadataLastModified, info.LastModified)
	if len(info.Tags) > 0 {
		set(adapter.MetadataTags, strings.Join(info.Tags, ","))
	}
	if info.CardData != nil {
		switch v := info.CardData["license"].(type) {
		case string:
			set(adapter.MetadataLicense, v)
		case []any:
			licenses := make([]string, 0, len(v))
			for _, l := range v {
				if s, ok := l.(string); ok {
					licenses = append(licenses, s)
				}
			}
			set(adapter.MetadataLicense, strings.Join(licenses, ","))
		}
		if md[adapter.MetadataLicense] == "" {
			if s, ok := info.CardData["license_name"].(string); ok {
				set(adapter.MetadataLicense, s)
			}
		}
	}
	// fall back to the "license:xxx" tag
	if md[adapter.MetadataLicense] == "" {
		for _, t := range info.Tags {
			if l, ok := strings.CutPrefix(t, "license:"); ok {
				set(adapter.MetadataLicense, l)
				break
			}
		}
	}
	return md
}

func (a *Adapter) getModelInfo(ctx context.Context, repo, rev string) (*modelInfo, error) {
	u := fmt.Sprintf("%s/api/models/%s/revision/%s", a.endpoint, repo, url.PathEscape(rev))
	resp, err := a.do(ctx, a.resolveClient, u, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, fmt.Sprintf("model %s@%s", repo, rev)); err != nil {
		return nil, err
	}
	info := &modelInfo{}
	if err := json.NewDecoder(resp.Body).Decode(info); err != nil {
		return nil, fmt.Errorf("failed to decode hugging face model info: %w", err)
	}
	return info, nil
}

func (a *Adapter) listTree(ctx context.Context, repo, sha string) ([]adapter.File, error) {
	next := fmt.Sprintf("%s/api/models/%s/tree/%s?recursive=true&limit=%d", a.endpoint, repo, sha, treePageSize)
	files := []adapter.File{}
	for next != "" {
		resp, err := a.do(ctx, a.resolveClient, next, nil)
		if err != nil {
			return nil, err
		}
		if err := checkStatus(resp, fmt.Sprintf("tree of %s@%s", repo, sha)); err != nil {
			resp.Body.Close()
			return nil, err
		}
		var entries []treeEntry
		err = json.NewDecoder(resp.Body).Decode(&entries)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to decode hugging face tree: %w", err)
		}
		for _, e := range entries {
			if e.Type != "file" {
				continue
			}
			f := adapter.File{Path: e.Path, Size: e.Size}
			if e.LFS != nil {
				f.SHA256 = e.LFS.OID
				if e.LFS.Size > 0 {
					f.Size = e.LFS.Size
				}
			}
			files = append(files, f)
		}
		next = nextLink(resp.Header.Get("Link"))
	}
	return files, nil
}

// nextLink parses the "next" URL out of a Link header.
func nextLink(header string) string {
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(part)
		if !strings.Contains(part, `rel="next"`) {
			continue
		}
		start := strings.Index(part, "<")
		end := strings.Index(part, ">")
		if start >= 0 && end > start {
			return part[start+1 : end]
		}
	}
	return ""
}

// FetchFile opens a streaming reader for the file at the resolved revision.
func (a *Adapter) FetchFile(ctx context.Context, rev *adapter.Revision, path string, offset int64) (io.ReadCloser, error) {
	if rev == nil || rev.ID == "" {
		return nil, fmt.Errorf("revision is required")
	}
	repo, err := repoFromSourceURL(a.endpoint, rev.SourceURL)
	if err != nil {
		return nil, err
	}
	// download by the immutable commit sha so a moving branch can't change the content
	u := fmt.Sprintf("%s/%s/resolve/%s/%s", a.endpoint, repo, rev.ID, escapePath(path))
	headers := map[string]string{}
	if offset > 0 {
		headers["Range"] = fmt.Sprintf("bytes=%d-", offset)
	}
	resp, err := a.do(ctx, a.fetchClient, u, headers)
	if err != nil {
		return nil, err
	}
	if err := checkStatus(resp, fmt.Sprintf("file %s of %s@%s", path, repo, rev.ID)); err != nil {
		resp.Body.Close()
		return nil, err
	}
	if offset > 0 && resp.StatusCode != http.StatusPartialContent {
		resp.Body.Close()
		return nil, fmt.Errorf("hugging face does not support range request for %s", path)
	}
	return resp.Body, nil
}

// repoFromSourceURL extracts the repository from the revision source URL built by ResolveModel.
func repoFromSourceURL(endpoint, sourceURL string) (string, error) {
	rest, ok := strings.CutPrefix(sourceURL, endpoint+"/")
	if !ok {
		return "", fmt.Errorf("unexpected source url %q", sourceURL)
	}
	idx := strings.Index(rest, "/tree/")
	if idx <= 0 {
		return "", fmt.Errorf("unexpected source url %q", sourceURL)
	}
	return rest[:idx], nil
}

func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

func (a *Adapter) do(ctx context.Context, client *http.Client, u string, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to request hugging face %s: %w", redact(u), err)
	}
	return resp, nil
}

func checkStatus(resp *http.Response, what string) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusNotFound:
		return errors.NotFoundError(nil).WithMessagef("%s not found on hugging face", what)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return errors.ForbiddenError(nil).WithMessagef("access to %s denied by hugging face (gated or private model, check the access token): %s", what, strings.TrimSpace(string(body)))
	case resp.StatusCode == http.StatusTooManyRequests:
		return fmt.Errorf("rate limited by hugging face when fetching %s", what)
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("unexpected status %d from hugging face when fetching %s: %s", resp.StatusCode, what, strings.TrimSpace(string(body)))
	}
}

func redact(u string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	parsed.RawQuery = ""
	return parsed.String()
}

// IsCommitSHA returns whether the revision is an immutable git commit sha.
func IsCommitSHA(rev string) bool {
	return shaRegexp.MatchString(rev)
}

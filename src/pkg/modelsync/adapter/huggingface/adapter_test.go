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

package huggingface

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/lib/errors"
	"github.com/goharbor/harbor/src/pkg/modelsync/adapter"
	"github.com/goharbor/harbor/src/pkg/reg/model"
)

const sha = "71034c5d8bde858ff824298bdedc65515b97d2b9"

func newHub(t *testing.T) (*httptest.Server, *[]string) {
	paths := &[]string{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/models/org/model/revision/main", func(w http.ResponseWriter, r *http.Request) {
		*paths = append(*paths, r.URL.RequestURI())
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "org/model", "sha": sha, "author": "org", "pipeline_tag": "text-generation",
			"library_name": "transformers", "tags": []string{"transformers", "license:apache-2.0"},
			"lastModified": "2024-04-08T18:00:37.000Z",
			"cardData":     map[string]any{"license": "apache-2.0"},
		})
	})
	mux.HandleFunc("/api/models/org/model/revision/missing", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/api/models/org/model/tree/"+sha, func(w http.ResponseWriter, r *http.Request) {
		*paths = append(*paths, r.URL.RequestURI())
		if r.URL.Query().Get("cursor") == "" {
			w.Header().Set("Link", fmt.Sprintf(`<http://%s/api/models/org/model/tree/%s?recursive=true&limit=1000&cursor=abc>; rel="next"`, r.Host, sha))
			fmt.Fprint(w, `[{"type":"directory","path":"sub","oid":"x"},{"type":"file","path":"sub/model.safetensors","size":10,"oid":"gitsha","lfs":{"oid":"aaaa","size":453864}}]`)
			return
		}
		fmt.Fprint(w, `[{"type":"file","path":"config.json","size":7,"oid":"gitsha2"}]`)
	})
	mux.HandleFunc("/org/model/resolve/"+sha+"/config.json", func(w http.ResponseWriter, r *http.Request) {
		*paths = append(*paths, r.URL.RequestURI())
		content := `{"a":1}`
		if rng := r.Header.Get("Range"); rng != "" {
			var off int
			fmt.Sscanf(rng, "bytes=%d-", &off)
			w.WriteHeader(http.StatusPartialContent)
			fmt.Fprint(w, content[off:])
			return
		}
		fmt.Fprint(w, content)
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, paths
}

func newAdapter(url, token string) *Adapter {
	return New(&model.Registry{Type: model.RegistryTypeHuggingFace, URL: url, Credential: &model.Credential{AccessSecret: token}})
}

func TestRegistered(t *testing.T) {
	a, err := adapter.Create(&model.Registry{Type: model.RegistryTypeHuggingFace})
	require.NoError(t, err)
	info, err := a.Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, model.RegistryTypeHuggingFace, info.Type)
	assert.Equal(t, DefaultRevision, info.DefaultRevision)
}

func TestResolveModel(t *testing.T) {
	server, paths := newHub(t)
	a := newAdapter(server.URL, "tok")
	ctx := context.Background()

	rev, err := a.ResolveModel(ctx, adapter.ModelRef{Repository: "org/model"})
	require.NoError(t, err)
	assert.Equal(t, "main", rev.Ref)
	assert.Equal(t, sha, rev.ID)
	assert.Equal(t, server.URL+"/org/model/tree/"+sha, rev.SourceURL)
	// directories skipped, files sorted, lfs digest and size used, pagination followed
	require.Len(t, rev.Files, 2)
	assert.Equal(t, adapter.File{Path: "config.json", Size: 7}, rev.Files[0])
	assert.Equal(t, adapter.File{Path: "sub/model.safetensors", Size: 453864, SHA256: "aaaa"}, rev.Files[1])
	assert.Equal(t, "apache-2.0", rev.Metadata[adapter.MetadataLicense])
	assert.Equal(t, "text-generation", rev.Metadata[adapter.MetadataPipelineTag])
	assert.Equal(t, "transformers", rev.Metadata[adapter.MetadataLibrary])
	assert.Equal(t, "org", rev.Metadata[adapter.MetadataAuthor])
	assert.Equal(t, 3, len(*paths))

	// invalid repo
	_, err = a.ResolveModel(ctx, adapter.ModelRef{Repository: "a/b/c"})
	assert.True(t, errors.IsErr(err, errors.BadRequestCode))
	// not found
	_, err = a.ResolveModel(ctx, adapter.ModelRef{Repository: "org/model", Revision: "missing"})
	assert.True(t, errors.IsErr(err, errors.NotFoundCode))
	// unauthorized
	_, err = newAdapter(server.URL, "").ResolveModel(ctx, adapter.ModelRef{Repository: "org/model"})
	assert.True(t, errors.IsErr(err, errors.ForbiddenCode))
}

func TestFetchFile(t *testing.T) {
	server, _ := newHub(t)
	a := newAdapter(server.URL, "tok")
	ctx := context.Background()
	rev := &adapter.Revision{ID: sha, SourceURL: server.URL + "/org/model/tree/" + sha}

	rc, err := a.FetchFile(ctx, rev, "config.json", 0)
	require.NoError(t, err)
	data, _ := io.ReadAll(rc)
	rc.Close()
	assert.Equal(t, `{"a":1}`, string(data))

	rc, err = a.FetchFile(ctx, rev, "config.json", 3)
	require.NoError(t, err)
	data, _ = io.ReadAll(rc)
	rc.Close()
	assert.Equal(t, `":1}`, string(data))

	_, err = a.FetchFile(ctx, rev, "nope.bin", 0)
	assert.True(t, errors.IsErr(err, errors.NotFoundCode))
	_, err = a.FetchFile(ctx, nil, "config.json", 0)
	assert.Error(t, err)
}

func TestBuildMetadataLicenseFallback(t *testing.T) {
	md := buildMetadata(&modelInfo{Tags: []string{"x", "license:mit"}})
	assert.Equal(t, "mit", md[adapter.MetadataLicense])
	md = buildMetadata(&modelInfo{CardData: map[string]any{"license": []any{"mit", "apache-2.0"}}})
	assert.Equal(t, "mit,apache-2.0", md[adapter.MetadataLicense])
	md = buildMetadata(&modelInfo{CardData: map[string]any{"license": "other", "license_name": "custom"}})
	assert.Equal(t, "other", md[adapter.MetadataLicense])
}

func TestNextLink(t *testing.T) {
	assert.Equal(t, "", nextLink(""))
	assert.Equal(t, "http://x/next", nextLink(`<http://x/prev>; rel="prev", <http://x/next>; rel="next"`))
}

func TestHelpers(t *testing.T) {
	assert.True(t, IsCommitSHA(sha))
	assert.False(t, IsCommitSHA("main"))
	assert.Equal(t, "a/b%20c", escapePath("a/b c"))
	repo, err := repoFromSourceURL("https://hf.co", "https://hf.co/org/model/tree/abc")
	require.NoError(t, err)
	assert.Equal(t, "org/model", repo)
	_, err = repoFromSourceURL("https://hf.co", "https://other/org/model/tree/abc")
	assert.Error(t, err)
	assert.False(t, strings.Contains(redact("http://x/y?token=1"), "token"))
}

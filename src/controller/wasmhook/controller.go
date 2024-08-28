// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package wasmhook

import (
	"context"
	"errors"
	"io"

	"github.com/goharbor/harbor/src/controller/artifact"
	"github.com/goharbor/harbor/src/lib/q"
	"github.com/goharbor/harbor/src/pkg/registry"
)

var Ctl = NewController()

const (
	wasmLayerMediaType = "application/vnd.wasm.content.layer.v1+wasm"

	HookModePassThrough = "pass_through"
	HookModeBlock       = "block"

	HookActionAllow = "allow"
	HookActionDeny  = "deny"

	HookInjectBeforePull = "before_pull"
	HookInjectBeforePush = "before_push"
	HookInjectAfterPull  = "after_pull"
	HookInjectAfterPush  = "after_push"
)

type RuntimeRequest struct {
	Username    string `json:"username"`
	Repository  string `json:"repository"`
	Reference   string `json:"reference"`
	ProjectName string `json:"project_name"`
	Digest      string `json:"digest"`
	Tag         string `json:"tag"`
}

type RuntimeResponse struct {
	Action       string `json:"action"` // pass or block
	Reason       string `json:"reason"`
	RuntimeError string `json:"runtime_error"`
}

type WasmHook struct {
	Artifact    *artifact.Artifact
	WasmProgram []byte
	HookMode    string
}

type Controller interface {
	ListWasmHooks(ctx context.Context, hookInjectPoint string) ([]WasmHook, error)
}

func NewController() Controller {
	return &controller{
		artCtl: artifact.Ctl,
		regCli: registry.Cli,
	}
}

type controller struct {
	artCtl artifact.Controller
	regCli registry.Client
}

func (c *controller) ListWasmHooks(ctx context.Context, hookInjectPoint string) ([]WasmHook, error) {
	query := q.New(q.KeyWords{
		"runtime_hook":        true,
		"runtime_hook_points": q.NewFuzzyMatchValue(hookInjectPoint),
	})
	arts, err := c.artCtl.List(ctx, query, &artifact.Option{})
	if err != nil {
		return nil, err
	}

	wasmHooks := make([]WasmHook, 0, len(arts))
	for _, art := range arts {
		wasm, err := c.pullWasmProgram(ctx, art)
		if err != nil {
			return nil, err
		}

		wasmHooks = append(wasmHooks, WasmHook{
			Artifact:    art,
			WasmProgram: wasm,
			HookMode:    art.RuntimeHookMode,
		})
	}

	return wasmHooks, nil
}

func (c *controller) pullWasmProgram(ctx context.Context, art *artifact.Artifact) ([]byte, error) {
	mf, _, err := c.regCli.PullManifest(art.RepositoryName, art.Digest)
	if err != nil {
		return nil, err
	}

	for _, layer := range mf.References() {
		if layer.MediaType == wasmLayerMediaType {
			_, wasmReader, err := c.regCli.PullBlob(art.RepositoryName, string(layer.Digest))
			if err != nil {
				return nil, err
			}

			wasm, err := io.ReadAll(wasmReader)
			if err != nil {
				return nil, err
			}
			defer wasmReader.Close()

			return wasm, nil
		}
	}

	return nil, errors.New("no wasm layer found")
}

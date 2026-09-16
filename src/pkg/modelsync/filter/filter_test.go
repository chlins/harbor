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

package filter

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/goharbor/harbor/src/pkg/modelsync/adapter"
)

func TestValidate(t *testing.T) {
	assert.NoError(t, Validate(nil))
	assert.NoError(t, Validate([]string{"*.safetensors", "**/*.json"}))
	assert.Error(t, Validate([]string{""}))
	assert.Error(t, Validate([]string{"[a-"}))
}

func TestMatch(t *testing.T) {
	assert.True(t, Match(nil, "anything"))
	assert.True(t, Match([]string{"*.safetensors"}, "model.safetensors"))
	assert.True(t, Match([]string{"*.safetensors"}, "sub/dir/model.safetensors"))
	assert.False(t, Match([]string{"sub/*.safetensors"}, "sub/dir/model.safetensors"))
	assert.True(t, Match([]string{"sub/**/*.safetensors"}, "sub/dir/model.safetensors"))
	assert.True(t, Match([]string{"config.json", "*.bin"}, "pytorch_model.bin"))
	assert.False(t, Match([]string{"config.json"}, "tokenizer.json"))
}

func TestApply(t *testing.T) {
	files := []adapter.File{{Path: "README.md"}, {Path: "model.safetensors"}, {Path: "onnx/model.onnx"}}
	assert.Equal(t, files, Apply(nil, files))
	got := Apply([]string{"*.safetensors", "README.md"}, files)
	assert.Equal(t, []adapter.File{{Path: "README.md"}, {Path: "model.safetensors"}}, got)
}

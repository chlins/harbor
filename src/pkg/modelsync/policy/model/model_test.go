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

package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileFilters(t *testing.T) {
	p := &Policy{}
	filters, err := p.GetFileFilters()
	require.NoError(t, err)
	assert.Nil(t, filters)

	require.NoError(t, p.SetFileFilters([]string{"*.safetensors", "**/*.json"}))
	assert.Equal(t, `["*.safetensors","**/*.json"]`, p.FileFilters)
	filters, err = p.GetFileFilters()
	require.NoError(t, err)
	assert.Equal(t, []string{"*.safetensors", "**/*.json"}, filters)

	require.NoError(t, p.SetFileFilters(nil))
	assert.Equal(t, "", p.FileFilters)

	p.FileFilters = "not-json"
	_, err = p.GetFileFilters()
	assert.Error(t, err)
}

func TestDefaultDestRepository(t *testing.T) {
	assert.Equal(t, "qwen/qwen3-8b", DefaultDestRepository(" Qwen/Qwen3-8B/ "))
	assert.Equal(t, "gpt2", DefaultDestRepository("gpt2"))
}

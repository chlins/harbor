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

package modelsync

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgmodel "github.com/goharbor/harbor/src/pkg/modelsync/policy/model"
	regmodel "github.com/goharbor/harbor/src/pkg/reg/model"
)

func TestPolicyConversion(t *testing.T) {
	p := &Policy{
		ID: 1, Name: " qwen ", Registry: &regmodel.Registry{ID: 2}, SrcRepository: "/Qwen/Qwen3-8B/",
		FileFilters: []string{"*.safetensors"}, DestProjectID: 3, DestRepository: "/models/qwen/",
		TriggerType: pkgmodel.TriggerTypeScheduled, Cron: " 0 0 * * * * ",
	}
	dp, err := p.To()
	require.NoError(t, err)
	assert.Equal(t, "qwen", dp.Name)
	assert.Equal(t, int64(2), dp.RegistryID)
	assert.Equal(t, "Qwen/Qwen3-8B", dp.SrcRepository)
	assert.Equal(t, "models/qwen", dp.DestRepository)
	assert.Equal(t, `["*.safetensors"]`, dp.FileFilters)
	assert.Equal(t, "0 0 * * * *", dp.Cron)

	back := &Policy{}
	require.NoError(t, back.From(dp))
	assert.Equal(t, []string{"*.safetensors"}, back.FileFilters)
	assert.Equal(t, int64(2), back.Registry.ID)
	assert.True(t, back.IsScheduledTrigger())
	assert.Equal(t, "models/qwen", back.EffectiveDestRepository())
	back.DestRepository = ""
	back.DestProjectName = "library"
	assert.Equal(t, "library/qwen/qwen3-8b", back.FullDestRepository())

	assert.NoError(t, (&Policy{}).From(nil))
	dp.FileFilters = "bad"
	assert.Error(t, (&Policy{}).From(dp))
}

func TestPolicyValidate(t *testing.T) {
	valid := func() *Policy {
		return &Policy{Name: "n", Registry: &regmodel.Registry{ID: 1}, SrcRepository: "a/b", DestProjectID: 1, TriggerType: pkgmodel.TriggerTypeManual}
	}
	assert.NoError(t, valid().Validate())
	p := valid()
	p.Name = ""
	assert.Error(t, p.Validate())
	p = valid()
	p.Registry = nil
	assert.Error(t, p.Validate())
	p = valid()
	p.SrcRepository = " "
	assert.Error(t, p.Validate())
	p = valid()
	p.DestProjectID = 0
	assert.Error(t, p.Validate())
	p = valid()
	p.TriggerType = "event"
	assert.Error(t, p.Validate())
	p = valid()
	p.TriggerType = pkgmodel.TriggerTypeScheduled
	p.Cron = "bad"
	assert.Error(t, p.Validate())
	p.Cron = "0 0 * * * *"
	assert.NoError(t, p.Validate())
}

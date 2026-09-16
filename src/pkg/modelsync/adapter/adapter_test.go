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

package adapter

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/goharbor/harbor/src/pkg/reg/model"
)

type fakeAdapter struct{}

func (fakeAdapter) Info(context.Context) (*Info, error)                       { return &Info{Type: "fake"}, nil }
func (fakeAdapter) HealthCheck(context.Context) error                         { return nil }
func (fakeAdapter) ResolveModel(context.Context, ModelRef) (*Revision, error) { return nil, nil }
func (fakeAdapter) FetchFile(context.Context, *Revision, string, int64) (io.ReadCloser, error) {
	return nil, nil
}

func reset() {
	factoriesMu.Lock()
	defer factoriesMu.Unlock()
	factories = map[string]Factory{}
}

func TestRegisterFactory(t *testing.T) {
	reset()
	f := FactoryFunc(func(*model.Registry) (Adapter, error) { return fakeAdapter{}, nil })
	assert.Error(t, RegisterFactory("", f))
	assert.Error(t, RegisterFactory("fake", nil))
	assert.NoError(t, RegisterFactory("fake", f))
	assert.Error(t, RegisterFactory("fake", f))
}

func TestGetFactoryAndCreate(t *testing.T) {
	reset()
	f := FactoryFunc(func(*model.Registry) (Adapter, error) { return fakeAdapter{}, nil })
	require.NoError(t, RegisterFactory("fake", f))

	_, err := GetFactory("unknown")
	assert.ErrorIs(t, err, ErrNotFound)
	assert.False(t, HasFactory("unknown"))
	assert.True(t, HasFactory("fake"))

	_, err = Create(nil)
	assert.Error(t, err)
	_, err = Create(&model.Registry{Type: "unknown"})
	assert.ErrorIs(t, err, ErrNotFound)
	a, err := Create(&model.Registry{Type: "fake"})
	require.NoError(t, err)
	info, err := a.Info(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "fake", info.Type)
}

func TestListRegisteredTypes(t *testing.T) {
	reset()
	f := FactoryFunc(func(*model.Registry) (Adapter, error) { return fakeAdapter{}, nil })
	require.NoError(t, RegisterFactory("b", f))
	require.NoError(t, RegisterFactory("a", f))
	assert.Equal(t, []string{"a", "b"}, ListRegisteredTypes())
}

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

package scan

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/goharbor/harbor/src/controller/artifact"
	"github.com/goharbor/harbor/src/controller/artifact/processor/cnai"
	"github.com/goharbor/harbor/src/controller/artifact/processor/image"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
)

func TestArtifactMimeType(t *testing.T) {
	assert.Equal(t, "", ArtifactMimeType(nil))

	img := &artifact.Artifact{}
	img.Type = image.ArtifactTypeImage
	img.ManifestMediaType = v1.MimeTypeDockerArtifact
	assert.Equal(t, v1.MimeTypeDockerArtifact, ArtifactMimeType(img))

	model := &artifact.Artifact{}
	model.Type = cnai.ArtifactTypeCNAI
	model.ManifestMediaType = v1.MimeTypeOCIArtifact
	model.ArtifactType = v1.MimeTypeModelArtifact
	assert.Equal(t, v1.MimeTypeModelArtifact, ArtifactMimeType(model))
}

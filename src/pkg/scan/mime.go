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
	"github.com/goharbor/harbor/src/controller/artifact"
	"github.com/goharbor/harbor/src/controller/artifact/processor/cnai"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
)

// ArtifactMimeType returns the mime type used to match scanner capabilities and sent to the
// scanner adapter for the artifact. Images are identified by their manifest media type.
// CNCF model artifacts are stored as OCI manifests whose artifactType is the model manifest
// mime type, so that type is used instead of the generic OCI manifest media type.
func ArtifactMimeType(art *artifact.Artifact) string {
	if art == nil {
		return ""
	}
	if art.Type == cnai.ArtifactTypeCNAI {
		return v1.MimeTypeModelArtifact
	}
	return art.ManifestMediaType
}

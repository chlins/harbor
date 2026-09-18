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

	ar "github.com/goharbor/harbor/src/controller/artifact"
	"github.com/goharbor/harbor/src/controller/artifact/processor/cnai"
	"github.com/goharbor/harbor/src/controller/artifact/processor/image"
	v1 "github.com/goharbor/harbor/src/pkg/scan/rest/v1"
)

func TestResolveScanType(t *testing.T) {
	img := &ar.Artifact{}
	img.Type = image.ArtifactTypeImage
	model := &ar.Artifact{}
	model.Type = cnai.ArtifactTypeCNAI

	cases := []struct {
		name     string
		scanType string
		artifact *ar.Artifact
		want     string
	}{
		{"default image", "", img, v1.ScanTypeVulnerability},
		{"default model", "", model, v1.ScanTypeModelSecurity},
		{"vulnerability asked for model", v1.ScanTypeVulnerability, model, v1.ScanTypeModelSecurity},
		{"model-security asked for image", v1.ScanTypeModelSecurity, img, v1.ScanTypeVulnerability},
		{"sbom image", v1.ScanTypeSbom, img, v1.ScanTypeSbom},
		{"sbom model", v1.ScanTypeSbom, model, v1.ScanTypeSbom},
		{"nil artifact", "", nil, v1.ScanTypeVulnerability},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := &Options{ScanType: c.scanType}
			assert.Equal(t, c.want, o.resolveScanType(c.artifact))
			assert.Equal(t, c.want, o.GetScanType())
		})
	}
}

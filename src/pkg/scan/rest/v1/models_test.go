package v1

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsSupportedMimeType(t *testing.T) {
	// Test with a supported mime type
	assert.True(t, isSupportedMimeType(MimeTypeSBOMReport), "isSupportedMimeType should return true for supported mime types")

	// Test with an unsupported mime type
	assert.False(t, isSupportedMimeType("unsupported/mime-type"), "isSupportedMimeType should return false for unsupported mime types")
}

func TestConvertCapability(t *testing.T) {
	md := &ScannerAdapterMetadata{
		Capabilities: []*ScannerCapability{
			{Type: ScanTypeSbom},
			{Type: ScanTypeVulnerability},
			{Type: ScanTypeModelSecurity},
		},
	}
	result := md.ConvertCapability()
	assert.Equal(t, result[supportSBOM], true)
	assert.Equal(t, result[supportVulnerability], true)
	assert.Equal(t, result[supportModelSecurity], true)
}

func TestValidate(t *testing.T) {
	scanner := &Scanner{Name: "s", Vendor: "v", Version: "1"}
	cases := []struct {
		name string
		caps []*ScannerCapability
		ok   bool
	}{
		{"no capabilities", nil, false},
		{"image scanner", []*ScannerCapability{{
			ConsumesMimeTypes: []string{MimeTypeOCIArtifact, MimeTypeDockerArtifact},
			ProducesMimeTypes: []string{MimeTypeNativeReport},
		}}, true},
		{"model scanner", []*ScannerCapability{{
			Type:              ScanTypeModelSecurity,
			ConsumesMimeTypes: []string{MimeTypeModelArtifact},
			ProducesMimeTypes: []string{MimeTypeModelSecurityReport, MimeTypeModelRawReport},
		}, {
			Type:              ScanTypeSbom,
			ConsumesMimeTypes: []string{MimeTypeModelArtifact},
			ProducesMimeTypes: []string{MimeTypeSBOMReport},
		}}, true},
		{"unknown artifact mime", []*ScannerCapability{{
			ConsumesMimeTypes: []string{"application/vnd.foo"},
			ProducesMimeTypes: []string{MimeTypeNativeReport},
		}}, false},
		{"unknown report mime", []*ScannerCapability{{
			ConsumesMimeTypes: []string{MimeTypeModelArtifact},
			ProducesMimeTypes: []string{MimeTypeModelRawReport},
		}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			md := &ScannerAdapterMetadata{Scanner: scanner, Capabilities: c.caps}
			err := md.Validate()
			if c.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
	assert.Error(t, (&ScannerAdapterMetadata{}).Validate())
}

func TestIsModelMimeType(t *testing.T) {
	assert.True(t, IsModelMimeType(MimeTypeModelArtifact))
	assert.False(t, IsModelMimeType(MimeTypeOCIArtifact))
}

func TestConvertCapabilityOldScaner(t *testing.T) {
	md := &ScannerAdapterMetadata{
		Capabilities: []*ScannerCapability{
			{
				ConsumesMimeTypes: []string{"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"},
				ProducesMimeTypes: []string{MimeTypeNativeReport},
			},
		},
	}
	result := md.ConvertCapability()
	assert.Equal(t, result[supportSBOM], false)
	assert.Equal(t, result[supportVulnerability], true)
}

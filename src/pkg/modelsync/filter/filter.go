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

// Package filter implements the doublestar file filters of model sync policies.
package filter

import (
	"fmt"
	"path"
	"strings"

	"github.com/bmatcuk/doublestar"

	"github.com/goharbor/harbor/src/pkg/modelsync/adapter"
)

// Validate checks that all the patterns are valid doublestar patterns.
func Validate(patterns []string) error {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			return fmt.Errorf("empty file filter pattern")
		}
		if _, err := doublestar.Match(p, "x"); err != nil {
			return fmt.Errorf("invalid file filter pattern %q: %w", p, err)
		}
	}
	return nil
}

// Match returns whether the file path matches any of the patterns. A file is
// matched when the pattern matches its full path, or, for patterns without a
// path separator, its base name (so "*.safetensors" also matches nested files).
// An empty pattern list matches everything.
func Match(patterns []string, filePath string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if ok, _ := doublestar.Match(p, filePath); ok {
			return true
		}
		if !strings.Contains(p, "/") {
			if ok, _ := doublestar.Match(p, path.Base(filePath)); ok {
				return true
			}
		}
	}
	return false
}

// Apply returns the files that match the patterns, preserving order.
func Apply(patterns []string, files []adapter.File) []adapter.File {
	if len(patterns) == 0 {
		return files
	}
	result := make([]adapter.File, 0, len(files))
	for _, f := range files {
		if Match(patterns, f.Path) {
			result = append(result, f)
		}
	}
	return result
}

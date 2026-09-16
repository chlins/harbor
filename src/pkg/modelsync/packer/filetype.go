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

package packer

import (
	"path"
	"strings"

	modelspec "github.com/modelpack/model-spec/specs-go/v1"
)

// The file classification patterns below are adapted from modctl
// (https://github.com/modelpack/modctl, Apache-2.0), pkg/modelfile/constants.go,
// so that Harbor classifies files the same way the reference ModelPack tooling does.

// FileType is the model-spec class of a file.
type FileType int

const (
	// FileTypeWeight is a model weight file.
	FileTypeWeight FileType = iota
	// FileTypeConfig is a configuration file of the weights (tokenizer, config.json...).
	FileTypeConfig
	// FileTypeCode is a code file.
	FileTypeCode
	// FileTypeDoc is a documentation file.
	FileTypeDoc
)

// weightFileSizeThreshold is the size above which an unrecognized file is treated as weights.
const weightFileSizeThreshold int64 = 128 * 1024 * 1024

var configFilePatterns = []string{
	"*.json", "*.jsonl", "*.json5", "*.jsonc", "*.yaml", "*.yml", "*.toml", "*.ini",
	"*.config", "*.cfg", "*.conf", "*.properties", "*.props", "*.prop", "*.xml", "*.xsd", "*.rng",
	"*.modelcard", "*.meta", "*tokenizer.model*", "*.tiktoken", "vocab.txt", "merges.txt",
	"added_tokens.txt", "spiece.model", "sentencepiece*.model", "sentencepiece*.vocab",
	"tiktoken.model", "chat_template.jinja", "config.json.*", "*.hparams", "*.params",
	"*.hyperparams", "*.wandb", "*.mlflow", "*.tensorboard",
}

var weightFilePatterns = []string{
	"*.safetensors",
	"*.bin", "*.bin.*", "*.pt", "*.pth", "*.mar", "*.pte", "*.pt2", "*.ptl",
	"*.tflite", "*.h5", "*.hdf", "*.hdf5", "*.pb", "*.data-*", "*.index",
	"*.gguf", "*.gguf.*", "*.ggml", "*.ggmf", "*.ggjt", "*.q4_0", "*.q4_1", "*.q5_0", "*.q5_1",
	"*.q8_0", "*.f16", "*.f32",
	"*.ckpt", "*.checkpoint", "*.dist_ckpt", "tensor[0-9]*_[0-9]*",
	"*.tensor", "*.weights", "*.state", "*.embedding", "*.vocab",
	"*.ot", "*.engine", "*.trt", "*.onnx", "*.onnx_data*", "*.msgpack", "*.model", "*.pkl",
	"*.pickle", "*.keras", "*.joblib", "*.npy", "*.npz", "*.nc", "*.mlmodel", "*.coreml",
	"*.mil", "*.mleap", "*.surml", "*.llamafile", "*.llamafile.*", "*.caffemodel", "*.prototxt",
	"*.dlc", "*.circle", "*.nb",
	"*.arrow", "*.parquet", "*.ftz", "*.ark", "*.db",
}

var codeFilePatterns = []string{
	"*.py", "*.ipynb", "*.sh", "*.patch", "*.c", "*.h", "*.hxx", "*.cpp", "*.cc", "*.cxx",
	"*.c++", "*.hpp", "*.hh", "*.h++", "*.java", "*.js", "*.mjs", "*.cjs", "*.jsx", "*.ts",
	"*.tsx", "*.go", "*.rs", "*.swift", "*.rb", "*.php", "*.scala", "*.kt", "*.kts", "*.r",
	"*.m", "*.mm", "*.f", "*.f90", "*.f95", "*.f03", "*.f08", "*.jl", "*.lua", "*.pl", "*.pm",
	"*.cs", "*.vb", "*.dart", "*.groovy", "*.elm", "*.erl", "*.hrl", "*.ex", "*.exs", "*.hs",
	"*.lhs", "*.clj", "*.cljs", "*.cljc", "*.cl", "*.lisp", "*.lsp", "*.scm", "*.ss", "*.rkt",
	"*.sql", "*.psql", "*.mysql", "*.sqlite", "*.zig", "*.cu", "*.cuh",
	"*.bash", "*.zsh", "*.fish", "*.csh", "*.tcsh", "*.ksh", "*.ps1", "*.psm1", "*.psd1",
	"*.bat", "*.cmd", "*.vbs", "*.wsf", "*.applescript", "*.scpt", "*.awk", "*.sed", "*.expect",
	"*.env", "*.env.*", ".env*", "Makefile*", "*.dockerfile", "Dockerfile*", "*.mk", "*.cmake",
	"CMakeLists.txt", "*.gradle", "*.gradle.kts", "build.gradle*", "settings.gradle*", "*.sbt",
	"*.mill", "*.bazel", "*.bzl", "BUILD*", "WORKSPACE*", "*.buck", "BUCK*", "*.ninja", "*.gyp",
	"*.gypi", "*.waf", "wscript*", "package.json", "package-lock.json", "yarn.lock",
	"pnpm-lock.yaml", "requirements*.txt", "Pipfile*", "pyproject.toml", "setup.cfg", "tox.ini",
	"poetry.lock", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum", "composer.json",
	"composer.lock", "Gemfile*", "*.gemspec", "mix.exs", "mix.lock", "rebar.config", "rebar.lock",
	"*.so", "*.dll", "*.dylib", "*.lib", "*.a",
}

var docFilePatterns = []string{
	"*.txt", "*.md", "*.pdf", "LICENSE*", "README*", "SETUP*", "*requirements*", "*.log", "*.tfevents*",
	"*.doc", "*.docx", "*.docm", "*.dot", "*.dotx", "*.dotm", "*.rtf", "*.odt", "*.ott", "*.fodt",
	"*.pages", "*.wpd", "*.xls", "*.xlsx", "*.xlsm", "*.xlsb", "*.xlt", "*.xltx", "*.xltm", "*.ods",
	"*.ots", "*.fods", "*.numbers", "*.csv", "*.ppt", "*.pptx", "*.pptm", "*.pps", "*.ppsx", "*.ppsm",
	"*.pot", "*.potx", "*.potm", "*.odp", "*.otp", "*.fodp", "*.key", "*.epub", "*.mobi", "*.azw",
	"*.azw3", "*.fb2", "*.fb3", "*.lit", "*.pdb", "*.djvu", "*.djv", "*.html", "*.htm", "*.xhtml",
	"*.mhtml", "*.mht", "*.xsl", "*.xslt", "*.tex", "*.latex", "*.ltx", "*.bib", "*.rst",
	"*.asciidoc", "*.adoc", "*.textile", "*.wiki", "*.mediawiki", "*.org", "*.texi", "*.texinfo",
	"*.info", "*.man", "*.chm", "*.hlp", "*.xps", "*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp",
	"*.tiff", "*.ico", "*.webp", "*.heic", "*.heif", "*.hevc", "*.svg", "*.mp4", "*.mov", "*.avi",
	"*.mkv", "*.webm", "*.m4v", "*.flv", "*.wmv", "*.mpg", "*.mpeg",
}

func matchAny(name string, patterns []string) bool {
	name = strings.ToLower(name)
	for _, p := range patterns {
		if ok, err := path.Match(strings.ToLower(p), name); err == nil && ok {
			return true
		}
	}
	return false
}

// InferFileType determines the file type by matching the base name against the
// known patterns (config first, then weights, code and docs); unrecognized files
// larger than 128MB are treated as weights, smaller ones as code.
func InferFileType(filePath string, size int64) FileType {
	name := path.Base(filePath)
	switch {
	case matchAny(name, configFilePatterns):
		return FileTypeConfig
	case matchAny(name, weightFilePatterns):
		return FileTypeWeight
	case matchAny(name, codeFilePatterns):
		return FileTypeCode
	case matchAny(name, docFilePatterns):
		return FileTypeDoc
	default:
		if size > weightFileSizeThreshold {
			return FileTypeWeight
		}
		return FileTypeCode
	}
}

// MediaType returns the raw (uncompressed, unarchived) model-spec layer media
// type of the file type.
func (t FileType) MediaType() string {
	switch t {
	case FileTypeConfig:
		return modelspec.MediaTypeModelWeightConfigRaw
	case FileTypeCode:
		return modelspec.MediaTypeModelCodeRaw
	case FileTypeDoc:
		return modelspec.MediaTypeModelDocRaw
	default:
		return modelspec.MediaTypeModelWeightRaw
	}
}

// String ...
func (t FileType) String() string {
	switch t {
	case FileTypeConfig:
		return "config"
	case FileTypeCode:
		return "code"
	case FileTypeDoc:
		return "doc"
	default:
		return "weight"
	}
}

// IsIgnored returns whether the file is a hub-side bookkeeping file that is
// never packed (git metadata such as .gitattributes).
func IsIgnored(filePath string) bool {
	for _, seg := range strings.Split(filePath, "/") {
		if strings.HasPrefix(seg, ".git") {
			return true
		}
	}
	return false
}

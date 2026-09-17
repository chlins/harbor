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
import { Component, Input, OnInit } from '@angular/core';
import { finalize } from 'rxjs/operators';
import { AdditionLink } from 'ng-swagger-gen/models';
import { AdditionsService } from '../additions.service';
import { ErrorHandler } from '../../../../../../shared/units/error-handler';
import { FilesItem } from 'src/app/shared/services/interface';
import { formatSize } from 'src/app/shared/units/utils';

// Clarity icon shown for a file, chosen by its class (weights, configs, docs,
// code, ...) so the file list of a model is easier to scan.
const ICON_RULES: { icon: string; test: RegExp }[] = [
    {
        icon: 'certificate',
        test: /^(license|licence|notice|copying)(\.[a-z0-9]+)?$/i,
    },
    { icon: 'note', test: /^readme|\.(md|markdown|rst|txt|pdf|adoc)$/i },
    {
        icon: 'layers',
        test: /\.(safetensors|bin|gguf|ggml|pt|pth|ckpt|onnx|h5|hdf5|pb|tflite|msgpack|npy|npz|pkl|mlmodel|engine)(\.[0-9]+)?$/i,
    },
    {
        icon: 'cog',
        test: /^(config|generation_config|tokenizer|tokenizer_config|special_tokens_map|vocab|merges|params|chat_template)|\.(json|jsonl|yaml|yml|toml|ini|cfg|model|tiktoken|jinja)$/i,
    },
    {
        icon: 'code',
        test: /\.(py|ipynb|sh|js|ts|go|rs|c|cpp|h|java|cu|lua|rb)$/i,
    },
    { icon: 'table', test: /\.(csv|tsv|parquet|arrow|feather)$/i },
    { icon: 'file-zip', test: /\.(zip|tar|gz|tgz|bz2|xz|7z|zst)$/i },
    { icon: 'image', test: /\.(png|jpe?g|gif|svg|webp|bmp)$/i },
];

export function fileIcon(name: string): string {
    const base = (name || '').split('/').pop() || '';
    for (const rule of ICON_RULES) {
        if (rule.test.test(base)) {
            return rule.icon;
        }
    }
    return 'file';
}

@Component({
    selector: 'hbr-artifact-files',
    templateUrl: './files.component.html',
    styleUrls: ['./files.component.scss'],
    standalone: false,
})
export class ArtifactFilesComponent implements OnInit {
    @Input() filesLink: AdditionLink;
    filesList: FilesItem[] = [];
    loading: Boolean = false;
    expandedNodes: Set<string> = new Set();
    constructor(
        private errorHandler: ErrorHandler,
        private additionsService: AdditionsService
    ) {}

    ngOnInit(): void {
        this.getFiles();
    }
    getFiles() {
        if (this.filesLink && !this.filesLink.absolute && this.filesLink.href) {
            this.loading = true;
            this.additionsService
                .getDetailByLink(this.filesLink.href, false, false)
                .pipe(finalize(() => (this.loading = false)))
                .subscribe(
                    res => {
                        if (res && res.length) {
                            this.filesList = res;
                        }
                    },
                    error => {
                        this.errorHandler.error(error);
                    }
                );
        }
    }

    iconFor(file: FilesItem & { expanded?: boolean }): string {
        if (file.children) {
            return file.expanded ? 'folder-open' : 'folder';
        }
        return fileIcon(file.name);
    }

    getChildren(folder: any) {
        return folder.children || [];
    }

    sizeTransform(tagSize: string): string {
        return formatSize(tagSize);
    }

    toggleNodeExpansion(nodeName: string): void {
        if (this.expandedNodes.has(nodeName)) {
            this.expandedNodes.delete(nodeName);
        } else {
            this.expandedNodes.add(nodeName);
        }
    }
}

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
export class ArtifactBuildHistory {
    created: Date;
    created_by: string;
}
export interface ArtifactDependency {
    name: string;
    version: string;
    repository: string;
}
export interface Addition {
    type: string;
    data?: object;
}

export enum ADDITIONS {
    VULNERABILITIES = 'vulnerabilities',
    // the model security report of AI model artifacts, served by the vulnerabilities endpoint
    SECURITY = 'security',
    BUILD_HISTORY = 'build_history',
    SUMMARY = 'readme.md',
    VALUES = 'values.yaml',
    DEPENDENCIES = 'dependencies',
    SBOMS = 'sboms',
    LICENSE = 'license',
    FILES = 'files',
}

export interface ModelSecurityFinding {
    id: string;
    severity: string;
    message: string;
    why?: string;
    file?: string;
    location?: string;
    scanner?: string;
    details?: object;
    links?: string[];
}

export interface ModelSecuritySummary {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    files_scanned: number;
    bytes_scanned: number;
    scanners?: string[];
}

export interface ModelSecurityReport {
    generated_at: string;
    scanner: { name: string; vendor: string; version: string };
    severity: string;
    summary?: ModelSecuritySummary;
    findings: ModelSecurityFinding[];
}

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
import {
    ArtifactSbomType,
    getArtifactSbom,
    isCycloneDxSbom,
    isSpdxSbom,
} from './artifact';

describe('artifact sbom helpers', () => {
    const spdx = {
        spdxVersion: 'SPDX-2.3',
        SPDXID: 'SPDXRef-DOCUMENT',
        name: 'alpine:3.19',
        dataLicense: 'CC0-1.0',
        creationInfo: { created: '2026-09-18T00:00:00Z' },
        packages: [
            {
                name: 'busybox',
                versionInfo: '1.36',
                licenseConcluded: 'GPL-2.0',
            },
        ],
    };
    const cyclonedx = {
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        serialNumber: 'urn:uuid:1',
        metadata: {
            timestamp: '2026-09-18T07:00:06Z',
            component: {
                type: 'machine-learning-model',
                name: 'library/evil-model',
            },
        },
        components: [
            {
                'bom-ref': 'model.pkl',
                type: 'machine-learning-model',
                name: 'model.pkl',
                hashes: [{ alg: 'SHA-256', content: 'abc' }],
                licenses: [{ expression: 'Apache-2.0' }],
            },
            {
                'bom-ref': 'config.json',
                type: 'data',
                name: 'config.json',
                version: '1',
                licenses: [{ license: { id: 'MIT' } }],
            },
        ],
    };

    it('should detect the SBOM format', () => {
        expect(isSpdxSbom(spdx)).toBeTrue();
        expect(isCycloneDxSbom(spdx)).toBeFalse();
        expect(isSpdxSbom(cyclonedx)).toBeFalse();
        expect(isCycloneDxSbom(cyclonedx)).toBeTrue();
        expect(getArtifactSbom({ foo: 'bar' })).toBeNull();
        expect(getArtifactSbom(null)).toBeNull();
    });

    it('should convert an SPDX document', () => {
        const sbom = getArtifactSbom(spdx);
        expect(sbom.sbomType).toEqual(ArtifactSbomType.SPDX);
        expect(sbom.sbomName).toEqual('alpine:3.19');
        expect(sbom.sbomPackage.packages.length).toEqual(1);
        expect(sbom.sbomPackage.packages[0].versionInfo).toEqual('1.36');
    });

    it('should convert a CycloneDX BOM', () => {
        const sbom = getArtifactSbom(cyclonedx);
        expect(sbom.sbomType).toEqual(ArtifactSbomType.CYCLONEDX);
        expect(sbom.sbomVersion).toEqual('1.6');
        expect(sbom.sbomName).toEqual('library/evil-model');
        expect(sbom.sbomCreated).toEqual('2026-09-18T07:00:06Z');
        expect(sbom.sbomJsonRaw).toBe(cyclonedx);
        const packages = sbom.sbomPackage.packages;
        expect(packages.length).toEqual(2);
        expect(packages[0].name).toEqual('model.pkl');
        expect(packages[0].versionInfo).toEqual('sha256:abc');
        expect(packages[0].licenseConcluded).toEqual('Apache-2.0');
        expect(packages[1].versionInfo).toEqual('1');
        expect(packages[1].licenseConcluded).toEqual('MIT');
    });

    it('should default the name of a CycloneDX BOM without root component', () => {
        const sbom = getArtifactSbom({
            bomFormat: 'CycloneDX',
            components: [],
        });
        expect(sbom.sbomName).toEqual('sbom');
        expect(sbom.sbomPackage.packages).toEqual([]);
    });
});

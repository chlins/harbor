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
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { NO_ERRORS_SCHEMA } from '@angular/core';
import { AdditionsService } from '../additions.service';
import { of } from 'rxjs';
import { ArtifactFilesComponent, fileIcon } from './files.component';
import { AdditionLink } from '../../../../../../../../ng-swagger-gen/models/addition-link';
import { ErrorHandler } from '../../../../../../shared/units/error-handler';
import { SharedTestingModule } from '../../../../../../shared/shared.module';
import { FilesItem } from 'src/app/shared/services/interface';

describe('FilesComponent', () => {
    let component: ArtifactFilesComponent;
    let fixture: ComponentFixture<ArtifactFilesComponent>;
    const mockedLink: AdditionLink = {
        absolute: false,
        href: '/test',
    };
    const filesList: FilesItem[] = [
        {
            name: 'model',
            type: 'file',
            size: 988099584,
        },
        {
            name: 'README.md',
            type: 'file',
            size: 5632,
        },
        {
            name: 'foo',
            type: 'directory',
            children: [
                {
                    name: 'bar',
                    type: 'directory',
                    children: [
                        {
                            name: '1.txt',
                            type: 'file',
                            children: [
                                {
                                    name: '2.txt',
                                    type: 'file',
                                    children: [
                                        {
                                            name: '3.txt',
                                            type: 'file',
                                            children: [
                                                {
                                                    name: '4.txt',
                                                    type: 'file',
                                                    size: 2048,
                                                },
                                                {
                                                    name: '5.txt',
                                                    type: 'file',
                                                    size: 2048,
                                                },
                                            ],
                                        },
                                        {
                                            name: '2.txt',
                                            type: 'file',
                                            size: 2048,
                                        },
                                    ],
                                },
                            ],
                        },
                        {
                            name: '2.txt',
                            type: 'file',
                            size: 2048,
                        },
                    ],
                },
            ],
        },
    ];

    const fakedAdditionsService = {
        getDetailByLink() {
            return of(filesList);
        },
    };
    beforeEach(async () => {
        await TestBed.configureTestingModule({
            imports: [SharedTestingModule],
            declarations: [ArtifactFilesComponent],
            providers: [
                ErrorHandler,
                { provide: AdditionsService, useValue: fakedAdditionsService },
            ],
            schemas: [NO_ERRORS_SCHEMA],
        }).compileComponents();
    });

    beforeEach(() => {
        fixture = TestBed.createComponent(ArtifactFilesComponent);
        component = fixture.componentInstance;
        fixture.detectChanges();
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });
    it('should get files and render', async () => {
        component.filesLink = mockedLink;
        component.ngOnInit();
        fixture.detectChanges();
        await fixture.whenStable();
        fixture.detectChanges();
        expect(component.filesList?.length).toEqual(filesList.length);
    });

    it('should pick an icon by file name', () => {
        expect(fileIcon('LICENSE')).toEqual('certificate');
        expect(fileIcon('README.md')).toEqual('note');
        expect(fileIcon('model-00001-of-00002.safetensors')).toEqual('layers');
        expect(fileIcon('Qwen3-0.6B-Q8_0.gguf')).toEqual('layers');
        expect(fileIcon('config.json')).toEqual('cog');
        expect(fileIcon('tokenizer.model')).toEqual('cog');
        expect(fileIcon('params')).toEqual('cog');
        expect(fileIcon('modeling_qwen.py')).toEqual('code');
        expect(fileIcon('data.parquet')).toEqual('table');
        expect(fileIcon('weights.tar.gz')).toEqual('file-zip');
        expect(fileIcon('banner.png')).toEqual('image');
        expect(fileIcon('unknown.xyz')).toEqual('file');
        expect(fileIcon('')).toEqual('file');
    });
});

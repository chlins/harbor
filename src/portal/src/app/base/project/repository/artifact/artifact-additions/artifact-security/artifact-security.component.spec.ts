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
import { ClarityModule } from '@clr/angular';
import { of } from 'rxjs';
import {
    TranslateNoOpLoader,
    TranslateLoader,
    TranslateModule,
} from '@ngx-translate/core';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { ArtifactSecurityComponent } from './artifact-security.component';
import { AdditionsService } from '../additions.service';
import { UserPermissionService } from '../../../../../../shared/services';
import { AdditionLink } from '../../../../../../../../ng-swagger-gen/models/addition-link';
import { ErrorHandler } from '../../../../../../shared/units/error-handler';
import { MODEL_SECURITY_REPORT_MIME_TYPE } from '../../../../../../shared/units/utils';
import { ModelSecurityReport } from '../models';

describe('ArtifactSecurityComponent', () => {
    let component: ArtifactSecurityComponent;
    let fixture: ComponentFixture<ArtifactSecurityComponent>;
    const report: ModelSecurityReport = {
        generated_at: '2026-09-18T05:44:34Z',
        scanner: { name: 'ModelAudit', vendor: 'Promptfoo', version: '0.2.52' },
        severity: 'Critical',
        summary: {
            total: 2,
            critical: 1,
            high: 0,
            medium: 1,
            low: 0,
            files_scanned: 2,
            bytes_scanned: 89,
            scanners: ['manifest', 'pickle'],
        },
        findings: [
            {
                id: 'S309',
                severity: 'Medium',
                message: 'URL detected in model: http://evil.example/x',
                file: 'model.pkl',
                scanner: 'pickle',
            },
            {
                id: 'S201',
                severity: 'Critical',
                message:
                    'Found REDUCE opcode invoking dangerous global: posix.system',
                why: 'system access',
                file: 'model.pkl',
                location: 'pos 64',
                scanner: 'pickle',
                links: ['https://www.promptfoo.dev/docs/model-audit/scanners/'],
            },
        ],
    };
    const response = {};
    response[MODEL_SECURITY_REPORT_MIME_TYPE] = report;
    const mockedLink: AdditionLink = { absolute: false, href: '/test' };
    const fakedAdditionsService = {
        getDetailByLink() {
            return of(response);
        },
    };
    const fakedUserPermissionService = {
        hasProjectPermissions() {
            return of([true]);
        },
    };

    beforeEach(() => {
        TestBed.configureTestingModule({
            imports: [
                BrowserAnimationsModule,
                ClarityModule,
                TranslateModule.forRoot({
                    loader: {
                        provide: TranslateLoader,
                        useClass: TranslateNoOpLoader,
                    },
                }),
            ],
            declarations: [ArtifactSecurityComponent],
            providers: [
                ErrorHandler,
                { provide: AdditionsService, useValue: fakedAdditionsService },
                {
                    provide: UserPermissionService,
                    useValue: fakedUserPermissionService,
                },
            ],
            schemas: [NO_ERRORS_SCHEMA],
        }).compileComponents();
    });

    beforeEach(() => {
        fixture = TestBed.createComponent(ArtifactSecurityComponent);
        component = fixture.componentInstance;
        component.hasEnabledScanner = true;
        component.securityLink = mockedLink;
        component.ngOnInit();
        fixture.detectChanges();
    });

    it('should create', () => {
        expect(component).toBeTruthy();
    });

    it('should render the findings sorted by severity', async () => {
        fixture.detectChanges();
        await fixture.whenStable();
        expect(component.findings.length).toEqual(2);
        expect(component.findings[0].id).toEqual('S201');
        expect(component.scanner.name).toEqual('ModelAudit');
        const rows = fixture.nativeElement.getElementsByTagName('clr-dg-row');
        expect(rows.length).toEqual(2);
        const cols = fixture.nativeElement.querySelectorAll('clr-dg-column');
        expect(cols.length).toEqual(5);
    });

    it('should format the location of a finding', () => {
        expect(component.location(report.findings[1])).toEqual(
            'model.pkl (pos 64)'
        );
        expect(component.location(report.findings[0])).toEqual('model.pkl');
        expect(component.location(null)).toEqual('');
    });

    it('should pick the model report from the scan overview', () => {
        const overview = {};
        overview[MODEL_SECURITY_REPORT_MIME_TYPE] = { scan_status: 'Success' };
        expect(component.handleScanOverview(overview).scan_status).toEqual(
            'Success'
        );
        expect(component.handleScanOverview(null)).toBeNull();
    });

    it('scan button should show the right text', async () => {
        fixture.autoDetectChanges(true);
        const scanBtn: HTMLButtonElement =
            fixture.nativeElement.querySelector('#scan-btn');
        expect(scanBtn.innerText).toContain('SECURITY.SCAN_NOW');
    });
});

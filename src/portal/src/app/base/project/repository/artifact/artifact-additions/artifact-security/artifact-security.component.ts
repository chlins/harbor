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
import { Component, Input, OnDestroy, OnInit, ViewChild } from '@angular/core';
import {
    ClrDatagridComparatorInterface,
    ClrDatagridStateInterface,
    ClrLoadingState,
} from '@clr/angular';
import { finalize } from 'rxjs/operators';
import { Subscription } from 'rxjs';
import { AdditionsService } from '../additions.service';
import { AdditionLink } from '../../../../../../../../ng-swagger-gen/models/addition-link';
import { Artifact } from '../../../../../../../../ng-swagger-gen/models/artifact';
import {
    ScannerVo,
    UserPermissionService,
    USERSTATICPERMISSION,
} from '../../../../../../shared/services';
import { ErrorHandler } from '../../../../../../shared/units/error-handler';
import {
    getPageSizeFromLocalStorage,
    MODEL_SECURITY_REPORT_MIME_TYPE,
    PageSizeMapKeys,
    setPageSizeToLocalStorage,
    SEVERITY_LEVEL_MAP,
} from '../../../../../../shared/units/utils';
import { ResultBarChartComponent } from '../../vulnerability-scanning/result-bar-chart.component';
import {
    EventService,
    HarborEvent,
} from '../../../../../../services/event-service/event.service';
import { severityText } from '../../../../../left-side-nav/interrogation-services/vulnerability-database/security-hub.interface';
import { PAGE_SIZE_OPTIONS } from 'src/app/shared/entities/shared.const';
import { ModelSecurityFinding, ModelSecurityReport } from '../models';

/**
 * The "Security" tab of an AI model artifact: the findings of the model security
 * report (unsafe deserialization, embedded code, credentials, ...) produced by a
 * model scanner such as ModelAudit.
 */
@Component({
    selector: 'hbr-artifact-security',
    templateUrl: './artifact-security.component.html',
    styleUrls: ['./artifact-security.component.scss'],
    standalone: false,
})
export class ArtifactSecurityComponent implements OnInit, OnDestroy {
    @Input()
    securityLink: AdditionLink;
    @Input()
    projectName: string;
    @Input()
    projectId: number;
    @Input()
    repoName: string;
    @Input()
    digest: string;
    @Input() artifact: Artifact;
    @Input() scanBtnState: ClrLoadingState = ClrLoadingState.DEFAULT;
    @Input() hasEnabledScanner: boolean = false;

    report: ModelSecurityReport;
    scanner: ScannerVo;
    findings: ModelSecurityFinding[] = [];
    loading: boolean = false;
    severitySort: ClrDatagridComparatorInterface<ModelSecurityFinding>;
    hasScanningPermission: boolean = false;
    onSendingScanCommand: boolean = false;
    onSendingStopCommand: boolean = false;
    hasShowLoading: boolean = false;
    @ViewChild(ResultBarChartComponent)
    resultBarChartComponent: ResultBarChartComponent;
    sub: Subscription;
    hasViewInitWithDelay: boolean = false;
    pageSize: number = getPageSizeFromLocalStorage(
        PageSizeMapKeys.ARTIFACT_SECURITY_COMPONENT,
        25
    );
    clrPageSizeOptions: number[] = PAGE_SIZE_OPTIONS;
    readonly severityText = severityText;

    constructor(
        private errorHandler: ErrorHandler,
        private additionsService: AdditionsService,
        private userPermissionService: UserPermissionService,
        private eventService: EventService
    ) {
        const that = this;
        this.severitySort = {
            compare(a: ModelSecurityFinding, b: ModelSecurityFinding): number {
                return that.getLevel(a) - that.getLevel(b);
            },
        };
    }

    ngOnInit() {
        this.getReport();
        this.getScanningPermission();
        if (!this.sub) {
            this.sub = this.eventService.subscribe(
                HarborEvent.UPDATE_VULNERABILITY_INFO,
                (artifact: Artifact) => {
                    if (artifact?.digest === this.artifact?.digest) {
                        this.getReport();
                    }
                }
            );
        }
        setTimeout(() => {
            this.hasViewInitWithDelay = true;
        }, 0);
    }

    ngOnDestroy() {
        if (this.sub) {
            this.sub.unsubscribe();
            this.sub = null;
        }
    }

    getReport() {
        if (
            this.securityLink &&
            !this.securityLink.absolute &&
            this.securityLink.href
        ) {
            if (!this.hasShowLoading) {
                this.loading = true;
                this.hasShowLoading = true;
            }
            this.additionsService
                .getDetailByLink(this.securityLink.href, true, false)
                .pipe(
                    finalize(() => {
                        this.loading = false;
                        this.hasShowLoading = false;
                    })
                )
                .subscribe(
                    res => {
                        this.report = null;
                        this.findings = [];
                        this.scanner = null;
                        const report: ModelSecurityReport =
                            res?.[MODEL_SECURITY_REPORT_MIME_TYPE] ??
                            (res ? (Object.values(res)[0] as any) : null);
                        if (report) {
                            this.report = report;
                            this.findings = (report.findings || []).slice();
                            this.findings.sort(
                                (a, b) => this.getLevel(b) - this.getLevel(a)
                            );
                            this.scanner = report.scanner;
                        }
                    },
                    error => {
                        this.errorHandler.error(error);
                    }
                );
        }
    }

    getScanningPermission(): void {
        const permissions = [
            {
                resource: USERSTATICPERMISSION.REPOSITORY_TAG_SCAN_JOB.KEY,
                action: USERSTATICPERMISSION.REPOSITORY_TAG_SCAN_JOB.VALUE
                    .CREATE,
            },
        ];
        this.userPermissionService
            .hasProjectPermissions(this.projectId, permissions)
            .subscribe(
                (results: Array<boolean>) => {
                    this.hasScanningPermission = results[0];
                },
                error => this.errorHandler.error(error)
            );
    }

    getLevel(f: ModelSecurityFinding): number {
        if (f && f.severity && SEVERITY_LEVEL_MAP[f.severity]) {
            return SEVERITY_LEVEL_MAP[f.severity];
        }
        return 0;
    }

    refresh(): void {
        this.getReport();
    }

    scanNow() {
        this.onSendingScanCommand = true;
        this.eventService.publish(
            HarborEvent.START_SCAN_ARTIFACT,
            this.repoName + '/' + this.digest
        );
    }

    stopNow() {
        this.onSendingStopCommand = true;
        this.eventService.publish(
            HarborEvent.STOP_SCAN_ARTIFACT,
            this.repoName + '/' + this.digest
        );
    }

    scanOrStop() {
        if (this.isRunningState()) {
            this.stopNow();
        } else {
            this.scanNow();
        }
    }

    submitFinish(e: boolean) {
        this.onSendingScanCommand = e;
    }

    submitStopFinish(e: boolean) {
        this.onSendingStopCommand = e;
    }

    shouldShowBar(): boolean {
        return (
            this.hasViewInitWithDelay &&
            this.resultBarChartComponent &&
            (this.resultBarChartComponent.queued ||
                this.resultBarChartComponent.scanning ||
                this.resultBarChartComponent.error ||
                this.resultBarChartComponent.stopped)
        );
    }

    hasScanned(): boolean {
        return (
            this.hasViewInitWithDelay &&
            this.resultBarChartComponent &&
            !(
                this.resultBarChartComponent.completed ||
                this.resultBarChartComponent.error ||
                this.resultBarChartComponent.queued ||
                this.resultBarChartComponent.stopped ||
                this.resultBarChartComponent.scanning
            )
        );
    }

    isRunningState(): boolean {
        return (
            this.hasViewInitWithDelay &&
            this.resultBarChartComponent &&
            (this.resultBarChartComponent.queued ||
                this.resultBarChartComponent.scanning)
        );
    }

    canScan(): boolean {
        return (
            this.hasEnabledScanner &&
            this.hasScanningPermission &&
            !this.onSendingScanCommand
        );
    }

    handleScanOverview(scanOverview: any): any {
        if (scanOverview) {
            return (
                scanOverview[MODEL_SECURITY_REPORT_MIME_TYPE] ??
                Object.values(scanOverview)[0]
            );
        }
        return null;
    }

    getScannerInfo(scanner: ScannerVo): string {
        if (scanner) {
            if (scanner.name && scanner.version) {
                return `${scanner.name}@${scanner.version}`;
            }
            if (scanner.name && !scanner.version) {
                return `${scanner.name}`;
            }
        }
        return '';
    }

    location(f: ModelSecurityFinding): string {
        if (f?.file && f?.location) {
            return `${f.file} (${f.location})`;
        }
        return f?.file || f?.location || '';
    }

    load(state: ClrDatagridStateInterface) {
        if (state?.page?.size) {
            setPageSizeToLocalStorage(
                PageSizeMapKeys.ARTIFACT_SECURITY_COMPONENT,
                state.page.size
            );
        }
    }
}

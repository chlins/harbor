# Model Security Scanning and SBOM

Harbor scans AI model artifacts (CNCF ModelPack, artifact type `CNAI`) for security
issues and generates an SBOM for them, through the same pluggable scanner framework used
for container images. The reference scanner is
[harbor-scanner-modelaudit](https://github.com/chlins/harbor-scanner-modelaudit), an
adapter around [promptfoo ModelAudit](https://www.promptfoo.dev/docs/model-audit/). The
adapter is deployed out of tree and registered like any other scanner.

The design is described in [the proposal](proposals/model-security-scanning.md).

## Table of Contents

- [How it works](#how-it-works)
- [Scanner capabilities for models](#scanner-capabilities-for-models)
- [Scanner selection](#scanner-selection)
- [Model security report](#model-security-report)
- [SBOM for models](#sbom-for-models)
- [API](#api)
- [Portal](#portal)
- [Setup](#setup)
- [Testing](#testing)

## How it works

```
push / scan request
        │
        ▼
controller/scan.Scan ── scanner.GetRegistrationByArtifact ──▶ project scanner (Trivy)
        │                                                          │ no model capability
        │                                                          ▼
        │                                              first enabled scanner that has one (ModelAudit)
        ▼
scan job (jobservice) ──POST /api/v1/scan──▶ adapter ──pull layers──▶ registry
        │                                        │ modelaudit
        ◀──GET /scan/{id}/report (model report / SBOM)──┘
        ▼
scan_report (mime application/vnd.security.model.report+json; version=1.0)
sbom_report + accessory sbom.harbor (application/vnd.cyclonedx+json)
```

Everything downstream of the scanner selection (jobs, executions, tasks, report storage,
scan-on-push, scan all, retention of executions) is the existing scan machinery. The
differences are the scan type, the report mime type and the handler that interprets it.

## Scanner capabilities for models

A scanner adapter declares what it can scan in its `/api/v1/metadata`. Model scanners
consume the CNCF model manifest mime type and produce the model security report and/or
an SBOM report:

```json
{
  "capabilities": [
    {
      "type": "model-security",
      "consumes_mime_types": ["application/vnd.cncf.model.manifest.v1+json"],
      "produces_mime_types": ["application/vnd.security.model.report+json; version=1.0"]
    },
    {
      "type": "sbom",
      "consumes_mime_types": ["application/vnd.cncf.model.manifest.v1+json"],
      "produces_mime_types": ["application/vnd.security.sbom.report+json; version=1.0"]
    }
  ]
}
```

`pkg/scan/rest/v1` (`spec.go`, `models.go`): the constants `MimeTypeModelArtifact`,
`ScanTypeModelSecurity`, `MimeTypeModelSecurityReport`, `MimeTypeModelRawReport`.
`ScannerAdapterMetadata.Validate` requires every capability to consume at least one of
the docker, OCI or model manifest mime types (the docker manifest used to be mandatory)
and to produce a report mime type Harbor understands. `ConvertCapability` exposes
`support_model_security` in the scanner API, which the Portal uses for the "Model
Security" column of the scanner list.

Model artifacts are stored as OCI manifests whose `artifactType` is the model manifest
mime type, so `scan.ArtifactMimeType(artifact)` (`pkg/scan/mime.go`) returns the model
mime type for `CNAI` artifacts and the manifest media type otherwise. Every place that
matched capabilities against `artifact.ManifestMediaType` uses it now, and the scannable
allowlist in `controller/scan/checker.go` includes `CNAI`.

## Scanner selection

A project has one scanner (project metadata or the system default), but a project
routinely holds both images and models.
`scanner.Controller.GetRegistrationByArtifact(ctx, projectID, mimeType)`
(`controller/scanner/base_controller.go`) keeps the project scanner when it has a
capability for the artifact mime type and otherwise falls back to the first enabled
registration (by creation time) that has one. If none has, the project scanner is returned
so the callers report the usual "does not support scanning artifact with mime type" error.

`Scan`, `GetReport`, `GetScanLog`, the scannable checker (cached per project and mime
type) and the SBOM summary use it. Trivy stays the project / default scanner for images;
ModelAudit is registered once for the instance and picked implicitly for models.

The security scan type is resolved from the artifact kind
(`controller/scan/options.go`, `resolveScanType`): `vulnerability` for images,
`model-security` for models, `sbom` untouched. Scan on push, scan all and a plain
`POST .../scan` without `scan_type` therefore do the right thing for both kinds, and
asking for the other kind's type is corrected rather than rejected.

## Model security report

Mime type `application/vnd.security.model.report+json; version=1.0`, model in
`pkg/scan/modelsecurity/model`:

```json
{
  "generated_at": "2026-09-18T06:55:59Z",
  "scanner": {"name": "ModelAudit", "vendor": "Promptfoo", "version": "0.2.52"},
  "severity": "Critical",
  "summary": {"total": 3, "critical": 2, "high": 0, "medium": 1, "low": 0,
              "files_scanned": 2, "bytes_scanned": 89, "scanners": ["manifest", "pickle"]},
  "findings": [
    {"id": "S201", "severity": "Critical",
     "message": "Found REDUCE opcode invoking dangerous global: posix.system",
     "why": "...", "file": "model.pkl", "location": "pos 64", "scanner": "pickle",
     "details": {"opcode": "REDUCE", "module": "posix", "name": "system"},
     "links": ["https://www.promptfoo.dev/docs/model-audit/scanners/"]}
  ]
}
```

Severities are the vulnerability ones (`None`, `Low`, `Medium`, `High`, `Critical`).
ModelAudit maps `critical → Critical`, `warning → Medium`, `info → Low`; `info` findings
(URLs in a README and the like) are filtered out by the adapter by default.

`pkg/scan/modelsecurity` implements the scan `Handler` for the `model-security` type:

- `MakePlaceHolder` creates one `scan_report` row per report mime type the scanner
  produces (the report and, if offered, the raw ModelAudit JSON), refusing while a
  previous scan is still running.
- `PostScan` validates the report and recomputes `severity` and the summary counters from
  the findings, so the stored report is consistent whatever the adapter sent. Raw reports
  are stored as is.
- `GetSummary` builds the `scan_overview` entry through `pkg/scan/report`
  (`GenerateModelSecuritySummary`, `MergeModelSecuritySummary`). Its shape is the one of
  the vulnerability summary (`report_id`, `scan_status`, `severity`, `duration`,
  `summary.total`, `summary.summary[<severity>]`, `scanner`, `complete_percent`) so the
  artifact list and the API render images and models alike.
- Executions use the vendor type `MODEL_SCAN` (retention
  `MODEL_SCAN_EXECUTION_RETENTION_COUNT`, default 1) so the latest model scan, the latest
  vulnerability scan and the latest SBOM generation of an artifact are all kept.

The report data of non-vulnerability mime types is not passed through the relational
vulnerability converter (`controller/scan/base_controller.go`, `assembleReports`).

## SBOM for models

The `sbom` scan type already existed for images with a hard-coded SPDX format.
`pkg/scan/sbom` now picks the format per artifact kind: `application/spdx+json` for
images, `application/vnd.cyclonedx+json` for models (what ModelAudit produces natively).
The requested format is sent in the scan request parameters and in the report URL, the
format returned by the scanner is stored on the `sbom_report` row and as the
`io.goharbor.sbom.media-type` annotation of the `sbom.harbor` accessory. The accessory
is downloadable through `GET .../artifacts/{sbomDigest}/additions/sbom` as before.

The CycloneDX BOM lists one component per model file with its SHA-256, size, license and
ModelAudit properties, with the scanned OCI artifact as the root component.

## API

No new endpoints.

| Endpoint | Change |
| --- | --- |
| `POST /projects/{p}/repositories/{r}/artifacts/{ref}/scan` and `.../scan/stop` | `scan_type` accepts `model-security`; without it the type follows the artifact kind |
| `GET .../artifacts`, `GET .../artifacts/{ref}` with `with_scan_overview=true` | `X-Accept-Vulnerabilities` accepts `application/vnd.security.model.report+json; version=1.0`; models always get their model security summary under that key |
| `GET .../artifacts/{ref}/additions/vulnerabilities` | returns the model security report for models when the header asks for it; models expose it as the `security` addition link (no `vulnerabilities` link) |
| `GET /scanners`, `GET /scanners/{id}/metadata` | `capabilities.support_model_security`, `model-security` capability type |

Model scans use the `scan` RBAC resource like vulnerability scans; SBOM generation uses
`sbom`.

```bash
H=https://harbor.example.com; A="$H/api/v2.0/projects/library/repositories/my-model/artifacts/v1"
curl -u admin:*** -X POST "$A/scan" -H 'Content-Type: application/json' -d '{"scan_type":"model-security"}'
curl -u admin:*** "$A?with_scan_overview=true" -H 'X-Accept-Vulnerabilities: application/vnd.security.model.report+json; version=1.0'
curl -u admin:*** "$A/additions/vulnerabilities"  -H 'X-Accept-Vulnerabilities: application/vnd.security.model.report+json; version=1.0'
curl -u admin:*** -X POST "$A/scan" -H 'Content-Type: application/json' -d '{"scan_type":"sbom"}'
```

## Portal

- Model artifact page: a **Security** tab (instead of Vulnerabilities) listing the
  findings with id, severity, file and position, message and check, the reason and
  details in the expanded row, and the Scan / Stop button and status bar
  (`artifact-additions/artifact-security`).
- Artifact list: the scan status bar and the Scan button work for models; the tooltip
  says "Security severity" and omits the fixable counter.
- SBOM tab: CycloneDX BOMs are rendered (component, version or SHA-256, license) next to
  SPDX ones.
- Scanners list: a "Model Security" capability column; the metadata panel names the
  `model-security` capability.
- Project settings: "Automatically scan artifacts on push" / auto SBOM wording covers
  images and models.

## Setup

1. Run the adapter next to Harbor (same network as `core` and `jobservice`), for example:

   ```bash
   docker run -d --name modelaudit-adapter --network harbor_harbor \
     -e SCANNER_REDIS_URL=redis://redis:6379/6 \
     ghcr.io/chlins/harbor-scanner-modelaudit:latest
   ```

   See the adapter README for the `SCANNER_*` settings (timeouts, size limit, minimum
   severity, scratch directory).
2. Register it: Administration → Interrogation Services → Scanners → New Scanner, endpoint
   `http://modelaudit-adapter:8080`, or `POST /api/v2.0/scanners`. Keep Trivy as the
   default scanner; ModelAudit is picked automatically for models. Do not make a
   model-only scanner the default or the project scanner unless the project holds only
   models.
3. Enable "Automatically scan artifacts on push" / "Automatically generate SBOM on push"
   on the projects that receive models, or scan on demand.

## Testing

```bash
# unit tests
cd src && go test ./pkg/scan/... ./controller/scan/... ./controller/scanner/... ./server/v2.0/handler/...
# (pkg/scan/report and a few others need Postgres, see tests/ci/ut_run.sh for the env vars)

# portal
cd src/portal && npx ng test --watch=false --include='src/app/base/project/repository/artifact/**/*.spec.ts'

# end to end against a running Harbor with a reachable adapter (needs oras)
cd tests/apitests/python
HARBOR_HOST=harbor.example.com MODELAUDIT_ADAPTER_URL=http://modelaudit-adapter:8080 \
  python -m pytest test_model_scan.py
```

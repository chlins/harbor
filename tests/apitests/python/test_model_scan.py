from __future__ import absolute_import
import json
import os
import pickle
import time
import unittest

import v2_swagger_client
from testutils import ADMIN_CLIENT, TEARDOWN, harbor_server, suppress_urllib3_warning
from library import base
from library.artifact import Artifact
from library.project import Project
from library.repository import Repository
from library.scan import Scan
from library.scanner import Scanner

# URL of a running harbor-scanner-modelaudit adapter, reachable from Harbor core,
# e.g. http://modelaudit-adapter:8080. The test is skipped when it is not set.
MODELAUDIT_ADAPTER_URL = os.environ.get("MODELAUDIT_ADAPTER_URL", "")
MODEL_REPORT_MIME_TYPE = "application/vnd.security.model.report+json; version=1.0"
MODEL_MANIFEST_MIME_TYPE = "application/vnd.cncf.model.manifest.v1+json"


class _Evil(object):
    # a pickle that calls os.system when loaded, flagged as Critical by ModelAudit
    def __reduce__(self):
        return (os.system, ("echo pwned",))


def push_model(project, repo, tag):
    workdir = "model-scan-{}".format(int(time.time()))
    os.makedirs(workdir, exist_ok=True)
    cwd = os.getcwd()
    os.chdir(workdir)
    try:
        with open("model.pkl", "wb") as f:
            f.write(pickle.dumps(_Evil()))
        with open("config.json", "w") as f:
            f.write(json.dumps({"model_type": "gpt2"}))
        with open("model-config.json", "w") as f:
            f.write(json.dumps({"descriptor": {"name": repo, "version": tag}, "modelfs": {"type": "layers", "diffIds": []},
                                "config": {"architecture": "gpt2", "format": "pickle"}}))
        with open("annotations.json", "w") as f:
            f.write(json.dumps({"model.pkl": {"org.cncf.model.filepath": "model.pkl"},
                                "config.json": {"org.cncf.model.filepath": "config.json"}}))
        base.run_command(["oras", "login", "-u", ADMIN_CLIENT["username"], "-p", ADMIN_CLIENT["password"], harbor_server])
        base.run_command(["oras", "push", "{}/{}/{}:{}".format(harbor_server, project, repo, tag),
                          "--artifact-type", MODEL_MANIFEST_MIME_TYPE,
                          "--config", "model-config.json:application/vnd.cncf.model.config.v1+json",
                          "--annotation-file", "annotations.json",
                          "model.pkl:application/vnd.cncf.model.weight.v1.raw",
                          "config.json:application/vnd.cncf.model.weight.config.v1.raw"])
    finally:
        os.chdir(cwd)


@unittest.skipIf(not MODELAUDIT_ADAPTER_URL, "MODELAUDIT_ADAPTER_URL is not set")
class TestModelScan(unittest.TestCase):
    scanner_id = None
    project_id = None
    project_name = None
    repo_name = "evil-model"
    tag = "v1"

    @suppress_urllib3_warning
    def setUp(self):
        self.project = Project()
        self.repo = Repository()
        self.artifact = Artifact()
        self.scan = Scan()
        self.scanner = Scanner()

    @unittest.skipIf(TEARDOWN == False, "Test data won't be erased.")
    def do_tearDown(self):
        self.repo.delete_repository(TestModelScan.project_name, TestModelScan.repo_name, **ADMIN_CLIENT)
        self.project.delete_project(TestModelScan.project_id, **ADMIN_CLIENT)
        if TestModelScan.scanner_id:
            self.scanner.delete_scanner(TestModelScan.scanner_id, **ADMIN_CLIENT)

    def testModelScan(self):
        """
        Test case:
            Model Security Scan And SBOM Of An AI Model Artifact
        Test step and expected result:
            1. Register the ModelAudit scanner adapter (implicit fallback scanner for models), its
               metadata declares the model-security and sbom capabilities for the model manifest mime type;
            2. Push a ModelPack artifact containing a malicious pickle with oras into a new project;
            3. Trigger a model-security scan, the scan overview under the model report mime type turns Success
               with severity Critical and the summary counters, the report has a Critical finding on model.pkl;
            4. Generate the SBOM, the accessory is a CycloneDX BOM listing the model files;
            5. Push a second tag with auto scan and auto SBOM enabled, both run without an explicit scan type.
        Tear down:
            1. Delete repository, project and the scanner registration.
        """
        client = ADMIN_CLIENT

        # 1. register the adapter unless it is already there
        existing = self.scanner.get_scanner_by_url(MODELAUDIT_ADAPTER_URL, **client)
        if existing is None:
            TestModelScan.scanner_id = self.scanner.create_scanner(
                base._random_name("modelaudit"), MODELAUDIT_ADAPTER_URL, "ModelAudit test scanner", **client)
            scanner_id = TestModelScan.scanner_id
        else:
            scanner_id = existing.uuid
        metadata = self.scanner.get_scanner_metadata(scanner_id, **client)
        types = {c.type: c for c in metadata.capabilities}
        self.assertIn("model-security", types)
        self.assertIn("sbom", types)
        self.assertIn(MODEL_MANIFEST_MIME_TYPE, types["model-security"].consumes_mime_types)
        self.assertIn(MODEL_REPORT_MIME_TYPE, types["model-security"].produces_mime_types)

        # 2. push the model
        TestModelScan.project_id, TestModelScan.project_name = self.project.create_project(
            metadata={"public": "false", "auto_scan": "false", "auto_sbom_generation": "false"}, **client)
        push_model(TestModelScan.project_name, TestModelScan.repo_name, TestModelScan.tag)
        art = self.artifact.get_reference_info(TestModelScan.project_name, TestModelScan.repo_name, TestModelScan.tag, **client)
        self.assertEqual("CNAI", art.type)
        self.assertIn("security", art.addition_links)
        self.assertNotIn("vulnerabilities", art.addition_links)

        # 3. model security scan
        self.scan.scan_artifact(TestModelScan.project_name, TestModelScan.repo_name, TestModelScan.tag,
                                scan_type=v2_swagger_client.ScanType(scan_type="model-security"), **client)
        overview = self.wait_for_scan(TestModelScan.tag)
        self.assertEqual("Success", overview.scan_status)
        self.assertEqual("Critical", overview.severity)
        self.assertEqual("ModelAudit", overview.scanner.name)
        self.assertGreaterEqual(overview.summary.summary["Critical"], 1)
        self.assertEqual(overview.summary.total, sum(overview.summary.summary.values()))

        report = self.artifact.get_vulnerabilities_addition(TestModelScan.project_name, TestModelScan.repo_name, TestModelScan.tag,
                                                            x_accept_vulnerabilities=MODEL_REPORT_MIME_TYPE, **client)
        report = json.loads(report)[MODEL_REPORT_MIME_TYPE]
        self.assertEqual("Critical", report["severity"])
        findings = [f for f in report["findings"] if f["severity"] == "Critical" and f["file"] == "model.pkl"]
        self.assertTrue(findings, report["findings"])
        self.assertEqual(report["summary"]["files_scanned"], 2)

        # 4. sbom
        self.scan.sbom_generation_of_artifact(TestModelScan.project_name, TestModelScan.repo_name, TestModelScan.tag, **client)
        self.artifact.check_image_sbom_generation_result(TestModelScan.project_name, TestModelScan.repo_name,
                                                          TestModelScan.tag, with_sbom_overview=True, **client)
        art = self.artifact.get_reference_info(TestModelScan.project_name, TestModelScan.repo_name, TestModelScan.tag,
                                               with_sbom_overview=True, with_accessory=True, **client)
        sbom_digest = art.sbom_overview.sbom_digest
        self.assertTrue(sbom_digest)
        sbom, status_code, _ = self.artifact.get_addition(TestModelScan.project_name, TestModelScan.repo_name, sbom_digest, "sbom", **client)
        self.assertEqual(200, status_code)
        sbom = json.loads(sbom)
        self.assertEqual("CycloneDX", sbom["bomFormat"])
        self.assertEqual({"model.pkl", "config.json"}, {c["name"] for c in sbom["components"]})

        # 5. scan on push and auto sbom
        self.project.update_project(TestModelScan.project_id, metadata={"auto_scan": "true", "auto_sbom_generation": "true"}, **client)
        push_model(TestModelScan.project_name, TestModelScan.repo_name, "v2")
        overview = self.wait_for_scan("v2")
        self.assertEqual("Success", overview.scan_status)
        self.assertEqual("Critical", overview.severity)
        self.artifact.check_image_sbom_generation_result(TestModelScan.project_name, TestModelScan.repo_name, "v2",
                                                          with_sbom_overview=True, **client)

        self.do_tearDown()

    def wait_for_scan(self, tag, timeout=300):
        deadline = time.time() + timeout
        overview = None
        while time.time() < deadline:
            time.sleep(5)
            art = self.artifact.get_reference_info(TestModelScan.project_name, TestModelScan.repo_name, tag,
                                                   with_scan_overview=True, x_accept_vulnerabilities=MODEL_REPORT_MIME_TYPE,
                                                   **ADMIN_CLIENT)
            if art.scan_overview:
                overview = art.scan_overview.get(MODEL_REPORT_MIME_TYPE)
                if overview and overview.scan_status in ("Success", "Error", "Stopped"):
                    return overview
        raise Exception("model scan of {} did not finish, last overview: {}".format(tag, overview))


if __name__ == '__main__':
    unittest.main()

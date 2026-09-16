from __future__ import absolute_import

import os
import unittest

from testutils import ADMIN_CLIENT, TEARDOWN, suppress_urllib3_warning
from library.registry import Registry
from library.model_sync import ModelSync
from library.project import Project
from library.repository import Repository
from library.artifact import Artifact

# a tiny public model used to validate the end to end sync; override to use a mirror
HF_ENDPOINT = os.environ.get("HF_ENDPOINT", "https://huggingface.co")
HF_MODEL = os.environ.get("HF_MODEL", "hf-internal-testing/tiny-random-gpt2")


class TestModelSync(unittest.TestCase):
    @suppress_urllib3_warning
    def setUp(self):
        self.registry = Registry()
        self.model_sync = ModelSync()
        self.project = Project()
        self.repo = Repository()
        self.artifact = Artifact()

    @unittest.skipIf(TEARDOWN == False, "Test data won't be erased.")
    def tearDown(self):
        # 1. delete the policy (its executions are deleted with it)
        self.model_sync.delete_policy(TestModelSync.policy_id, **ADMIN_CLIENT)
        # 2. delete the synced repository and the project
        try:
            self.repo.delete_repository(TestModelSync.project_name, TestModelSync.dest_repository, **ADMIN_CLIENT)
        except Exception:
            pass
        self.project.delete_project(TestModelSync.project_id, **ADMIN_CLIENT)
        # 3. delete the registry
        self.registry.delete_registry(TestModelSync.registry_id, **ADMIN_CLIENT)

    def testModelSync(self):
        """
        Test case:
            Model sync from Hugging Face
        Test step and expected result:
            1. Register a huggingface registry, it must not appear as a replication candidate but must
               be listed as a model sync adapter;
            2. Create a project;
            3. Preview the model source, the resolved revision and the filtered files are returned;
            4. Create a model sync policy with a manual trigger and file filters, get/list/update it;
            5. Trigger the sync, wait for the execution to succeed, one task with revision, digest and tags;
            6. The artifact exists in the destination repository with the sha-<12> tag and the policy
               cursor is advanced;
            7. Trigger the sync again, the task is skipped because the revision is unchanged.
        Tear down:
            1. Delete the policy;
            2. Delete the repository and project;
            3. Delete the registry.
        """
        # 1
        TestModelSync.registry_id, _ = self.registry.create_registry(
            HF_ENDPOINT, registry_type="huggingface", access_key="token", access_secret="", insecure=False, **ADMIN_CLIENT)
        adapters = self.model_sync.list_adapters(**ADMIN_CLIENT)
        self.assertIn("huggingface", adapters)

        # 2
        TestModelSync.project_name = "model-sync-" + os.urandom(3).hex()
        TestModelSync.project_id, _ = self.project.create_project(name=TestModelSync.project_name, metadata={"public": "false"}, **ADMIN_CLIENT)

        # 3
        preview = self.model_sync.preview(TestModelSync.registry_id, HF_MODEL, file_filters=["*.json", "README.md"], **ADMIN_CLIENT)
        self.assertEqual(len(preview.revision), 40)
        self.assertGreater(preview.total_files, 0)
        self.assertGreater(preview.matched_files, 0)
        self.assertLessEqual(preview.matched_files, preview.total_files)
        self.assertTrue(any(t.startswith("sha-") for t in preview.tags))

        # 4
        TestModelSync.policy_id, policy = self.model_sync.create_policy(
            TestModelSync.registry_id, HF_MODEL, TestModelSync.project_id,
            file_filters=["*.json", "README.md"], **ADMIN_CLIENT)
        got = self.model_sync.get_policy(TestModelSync.policy_id, **ADMIN_CLIENT)
        self.assertEqual(got.name, policy.name)
        self.assertEqual(got.registry_id, TestModelSync.registry_id)
        self.assertEqual(got.dest_project_name, TestModelSync.project_name)
        self.assertEqual(got.dest_repository, HF_MODEL.lower())
        # the credential must never be exposed in clear text
        if got.registry.credential:
            self.assertIn(got.registry.credential.access_secret, (None, "", "*****"))
        TestModelSync.dest_repository = got.dest_repository
        self.assertTrue(any(p.id == TestModelSync.policy_id for p in self.model_sync.list_policies(**ADMIN_CLIENT)))
        got.description = "updated"
        self.model_sync.update_policy(TestModelSync.policy_id, got, **ADMIN_CLIENT)
        self.assertEqual(self.model_sync.get_policy(TestModelSync.policy_id, **ADMIN_CLIENT).description, "updated")

        # 5
        execution_id = self.model_sync.start(TestModelSync.policy_id, **ADMIN_CLIENT)
        execution = self.model_sync.wait_until_execution_finish(execution_id, **ADMIN_CLIENT)
        tasks = self.model_sync.list_tasks(execution_id, **ADMIN_CLIENT)
        self.assertEqual(len(tasks), 1)
        log = self.model_sync.get_task_log(execution_id, tasks[0].id, **ADMIN_CLIENT)
        self.assertEqual(execution.status, "Succeed", "execution failed: %s\n%s" % (execution.status_text, log))
        task = tasks[0]
        self.assertEqual(task.revision, preview.revision)
        self.assertTrue(task.digest.startswith("sha256:"))
        self.assertIn("sha-" + preview.revision[:12], task.tags)
        self.assertFalse(task.skipped)

        # 6
        artifact = self.artifact.get_reference_info(TestModelSync.project_name, TestModelSync.dest_repository, "sha-" + preview.revision[:12], **ADMIN_CLIENT)
        self.assertEqual(artifact.digest, task.digest)
        self.assertEqual(self.model_sync.get_policy(TestModelSync.policy_id, **ADMIN_CLIENT).last_synced_revision, preview.revision)

        # 7
        execution_id = self.model_sync.start(TestModelSync.policy_id, **ADMIN_CLIENT)
        execution = self.model_sync.wait_until_execution_finish(execution_id, **ADMIN_CLIENT)
        self.assertEqual(execution.status, "Succeed")
        tasks = self.model_sync.list_tasks(execution_id, **ADMIN_CLIENT)
        self.assertEqual(len(tasks), 1)
        self.assertTrue(tasks[0].skipped)
        self.assertEqual(tasks[0].digest, task.digest)


if __name__ == '__main__':
    unittest.main()

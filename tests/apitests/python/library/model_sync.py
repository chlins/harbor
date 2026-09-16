# -*- coding: utf-8 -*-

import time

import base
import v2_swagger_client


class ModelSync(base.Base, object):
    def __init__(self):
        super(ModelSync, self).__init__(api_type="model_sync")

    def create_policy(self, registry_id, src_repository, dest_project_id, name=None, src_revision="",
                      file_filters=None, dest_repository="", trigger_type="manual", cron="", enabled=True,
                      expect_status_code=201, **kwargs):
        client = self._get_client(**kwargs)
        trigger = v2_swagger_client.ModelSyncTrigger(type=trigger_type)
        if trigger_type == "scheduled":
            trigger.trigger_settings = v2_swagger_client.ModelSyncTriggerTriggerSettings(cron=cron)
        policy = v2_swagger_client.ModelSyncPolicy(
            name=name or base._random_name("model-sync"),
            registry_id=registry_id,
            src_repository=src_repository,
            src_revision=src_revision,
            file_filters=file_filters or [],
            dest_project_id=dest_project_id,
            dest_repository=dest_repository,
            trigger=trigger,
            enabled=enabled,
        )
        _, status_code, header = client.create_model_sync_policy_with_http_info(policy)
        base._assert_status_code(expect_status_code, status_code)
        return base._get_id_from_header(header), policy

    def get_policy(self, policy_id, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        data, status_code, _ = client.get_model_sync_policy_with_http_info(policy_id)
        base._assert_status_code(expect_status_code, status_code)
        return data

    def list_policies(self, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        data, status_code, _ = client.list_model_sync_policies_with_http_info()
        base._assert_status_code(expect_status_code, status_code)
        return data

    def update_policy(self, policy_id, policy, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        _, status_code, _ = client.update_model_sync_policy_with_http_info(policy_id, policy)
        base._assert_status_code(expect_status_code, status_code)

    def delete_policy(self, policy_id, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        _, status_code, _ = client.delete_model_sync_policy_with_http_info(policy_id)
        base._assert_status_code(expect_status_code, status_code)

    def preview(self, registry_id, src_repository, src_revision="", file_filters=None, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        req = v2_swagger_client.ModelSyncPreviewRequest(registry_id=registry_id, src_repository=src_repository,
                                                        src_revision=src_revision, file_filters=file_filters or [])
        data, status_code, _ = client.preview_model_sync_with_http_info(req)
        base._assert_status_code(expect_status_code, status_code)
        return data

    def list_adapters(self, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        data, status_code, _ = client.list_model_sync_adapters_with_http_info()
        base._assert_status_code(expect_status_code, status_code)
        return data

    def start(self, policy_id, expect_status_code=201, **kwargs):
        client = self._get_client(**kwargs)
        _, status_code, header = client.start_model_sync_with_http_info(policy_id)
        base._assert_status_code(expect_status_code, status_code)
        return base._get_id_from_header(header)

    def list_executions(self, policy_id, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        data, status_code, _ = client.list_model_sync_executions_with_http_info(policy_id)
        base._assert_status_code(expect_status_code, status_code)
        return data

    def get_execution(self, execution_id, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        data, status_code, _ = client.get_model_sync_execution_with_http_info(execution_id)
        base._assert_status_code(expect_status_code, status_code)
        return data

    def list_tasks(self, execution_id, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        data, status_code, _ = client.list_model_sync_tasks_with_http_info(execution_id)
        base._assert_status_code(expect_status_code, status_code)
        return data

    def get_task_log(self, execution_id, task_id, expect_status_code=200, **kwargs):
        client = self._get_client(**kwargs)
        data, status_code, _ = client.get_model_sync_log_with_http_info(execution_id, task_id)
        base._assert_status_code(expect_status_code, status_code)
        return data

    def wait_until_execution_finish(self, execution_id, timeout=600, interval=10, **kwargs):
        deadline = time.time() + timeout
        while time.time() < deadline:
            execution = self.get_execution(execution_id, **kwargs)
            if execution.status in ("Succeed", "Failed", "Stopped"):
                return execution
            time.sleep(interval)
        raise Exception("model sync execution %s did not finish in %ss" % (execution_id, timeout))

# -*- coding: utf-8 -*-

import base
import v2_swagger_client
from v2_swagger_client.rest import ApiException


class Scanner(base.Base, object):
    def __init__(self):
        super(Scanner, self).__init__(api_type="scanner")

    def list_scanners(self, **kwargs):
        data, status_code, _ = self._get_client(**kwargs).list_scanners_with_http_info()
        base._assert_status_code(200, status_code)
        return data

    def get_scanner_by_url(self, url, **kwargs):
        for scanner in self.list_scanners(**kwargs):
            if scanner.url == url:
                return scanner
        return None

    def create_scanner(self, name, url, description="", use_internal_addr=False, expect_status_code=201, **kwargs):
        registration = v2_swagger_client.ScannerRegistrationReq(
            name=name, url=url, description=description, auth="", skip_cert_verify=True,
            use_internal_addr=use_internal_addr, disabled=False)
        try:
            _, status_code, header = self._get_client(**kwargs).create_scanner_with_http_info(registration)
        except ApiException as e:
            base._assert_status_code(expect_status_code, e.status)
            return None
        base._assert_status_code(expect_status_code, status_code)
        return base._get_id_from_header(header)

    def get_scanner_metadata(self, registration_id, **kwargs):
        data, status_code, _ = self._get_client(**kwargs).get_scanner_metadata_with_http_info(registration_id)
        base._assert_status_code(200, status_code)
        return data

    def delete_scanner(self, registration_id, expect_status_code=200, **kwargs):
        try:
            _, status_code, _ = self._get_client(**kwargs).delete_scanner_with_http_info(registration_id)
        except ApiException as e:
            base._assert_status_code(expect_status_code, e.status)
            return
        base._assert_status_code(expect_status_code, status_code)

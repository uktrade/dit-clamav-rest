import base64
from io import BytesIO
import unittest
import mock

import clamd
import clamav_rest


class ClamAVRESTTestCase(unittest.TestCase):
    EICAR = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    def _get_auth_header(self, username, password):
        creds = base64.b64encode(
            bytes("{}:{}".format(username, password), "utf-8"))

        return dict(Authorization=b'Basic ' + creds)

    def _get_file_data(self, file_name, data):
        return dict(
            file=(BytesIO(data), file_name))

    def setUp(self):
        clamav_rest.app.config['TESTING'] = True
        self.app = clamav_rest.app.test_client()

    def test_healthcheck(self):
        response = self.app.get("/")
        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.data, b'Service OK')

    @mock.patch("clamav_rest.cd.ping")
    def test_healthcheck_no_service(self, ping):
        ping.side_effect = clamd.ConnectionError()

        response = self.app.get("/")

        self.assertEquals(response.status_code, 200)
        self.assertEquals(response.data, b'Service Unavailable')

    def test_scan_endpoint_requires_post(self):
        response = self.app.get("/scan")

        self.assertEquals(response.status_code, 405)

    def test_auth_ok(self):
        response = self.app.post("/scan",
                                 headers=self._get_auth_header("app1", "letmein")
                                 )

        # expecting 400 as no file data
        self.assertEquals(response.status_code, 400)

    def test_auth_fail(self):
        response = self.app.post("/scan",
                                 headers=self._get_auth_header("app1", "WRONGPASSWORD")
                                 )

        self.assertEquals(response.status_code, 401)

    def test_eicar(self):
        response = self.app.post("/scan",
                                 headers=self._get_auth_header("app1", "letmein"),
                                 content_type='multipart/form-data',
                                 data=self._get_file_data("unsafe.txt", self.EICAR)
                                 )

        self.assertEquals(response.data, b"NOTOK")
        self.assertEquals(response.status_code, 200)

    def test_clean_data(self):
        response = self.app.post("/scan",
                                 headers=self._get_auth_header("app1", "letmein"),
                                 content_type='multipart/form-data',
                                 data=self._get_file_data("test.txt", b"NO VIRUS HERE")
                                 )
        self.assertEquals(response.data, b"OK")
        self.assertEquals(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()

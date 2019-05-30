import base64
import json
import unittest
from io import BytesIO

import clamd
import mock

import clamav_rest

EICAR = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def _get_auth_header(username, password):
    creds = base64.b64encode(
        bytes("{}:{}".format(username, password), "utf-8"))

    return dict(Authorization=b'Basic ' + creds)


def _get_file_data(file_name, data):
    return dict(
        file=(BytesIO(data), file_name))


def _read_file_data(file_name):
    with open(file_name, "rb") as binary_file:
        # Read the whole file at once
        data = binary_file.read()

    return dict(
        file=(BytesIO(data), file_name)
    )


class ClamAVirusUpdate(unittest.TestCase):

    def setUp(self):
        clamav_rest.app.config['Testing'] = True
        self.app = clamav_rest.app.test_client()

    @mock.patch("clamav_versions.ClamAVRemoteVersionService.parse_remote_version")
    @mock.patch("clamav_versions.ClamAVLocalVersionService.parse_local_version")
    def test_local_remote_services_are_insync(self, remote, local):
        remote.return_value = "3"
        local.return_value = "3"

        response = self.app.get("/health/definitions",
                                headers=_get_auth_header("app1", "letmein"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'3')

    @mock.patch("clamav_versions.ClamAVRemoteVersionService.parse_remote_version")
    @mock.patch("clamav_versions.ClamAVLocalVersionService.parse_local_version")
    def test_services_out_of_date(self, remote, local):
        remote.return_value = "3"
        local.return_value = "2"

        response = self.app.get("/health/definitions",
                                headers=_get_auth_header("app1", "letmein"))
        self.assertEqual(response.status_code, 500)

    def test_health_check_requires_auth(self):
        response = self.app.get("/health/definitions")

        self.assertEqual(response.status_code, 401)


class ClamAVRESTTestCase(unittest.TestCase):

    def setUp(self):
        clamav_rest.app.config['TESTING'] = True
        self.app = clamav_rest.app.test_client()

    def test_healthcheck(self):
        response = self.app.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'Service OK')

    @mock.patch("clamav_rest.cd.ping")
    def test_healthcheck_no_service(self, ping):
        ping.side_effect = clamd.ConnectionError()

        response = self.app.get("/")

        self.assertEqual(response.status_code, 502)
        self.assertEqual(response.data, b'Service Unavailable')

    @mock.patch("clamav_rest.cd.ping")
    def test_healthcheck_unexpected_error(self, ping):
        ping.side_effect = Exception("Oops")

        response = self.app.get("/")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.data, b'Service Unavailable')

    @mock.patch("clamav_rest.cd.ping")
    def test_healthcheck_unexpected_error(self, ping):
        ping.side_effect = Exception("Oops")

        response = self.app.get("/")

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.data, b'Service Unavailable')

    def test_scan_endpoint_requires_post(self):
        response = self.app.get("/scan")

        self.assertEqual(response.status_code, 405)

    def test_auth_ok(self):
        response = self.app.post("/scan",
                                 headers=_get_auth_header("app1", "letmein")
                                 )

        # expecting 400 as no file data
        self.assertEqual(response.status_code, 400)

    def test_auth_fail(self):
        response = self.app.post("/scan",
                                 headers=_get_auth_header(
                                     "app1", "WRONGPASSWORD")
                                 )

        self.assertEqual(response.status_code, 401)

    def test_eicar(self):
        response = self.app.post("/scan",
                                 headers=_get_auth_header("app1", "letmein"),
                                 content_type='multipart/form-data',
                                 data=_get_file_data("unsafe.txt", EICAR)
                                 )

        self.assertEqual(response.data, b"NOTOK")
        self.assertEqual(response.status_code, 200)

    def test_clean_data(self):
        response = self.app.post("/scan",
                                 headers=_get_auth_header("app1", "letmein"),
                                 content_type='multipart/form-data',
                                 data=_get_file_data(
                                     "test.txt", b"NO VIRUS HERE")
                                 )
        self.assertEqual(response.data, b"OK")
        self.assertEqual(response.status_code, 200)


class ClamAVRESTV2ScanTestCase(unittest.TestCase):
    def setUp(self):
        clamav_rest.app.config['TESTING'] = True
        self.app = clamav_rest.app.test_client()

    def test_encrypyed_archive(self):
        response = self.app.post("/v2/scan",
                                 headers=_get_auth_header("app1", "letmein"),
                                 content_type='multipart/form-data',
                                 data=_read_file_data(
                                     "client-examples/protected.zip")
                                 )

        data = json.loads(response.data.decode('utf8'))

        self.assertEqual(data['malware'], True)
        self.assertEqual(data['reason'], "Heuristics.Encrypted.Zip")

    def test_eicar(self):
        response = self.app.post("/v2/scan",
                                 headers=_get_auth_header("app1", "letmein"),
                                 content_type='multipart/form-data',
                                 data=_get_file_data(
                                     "eicar.txt", EICAR)
                                 )

        data = json.loads(response.data.decode('utf8'))

        self.assertEqual(data['malware'], True)
        self.assertEqual(data['reason'], "Eicar-Test-Signature")


if __name__ == '__main__':
    unittest.main()

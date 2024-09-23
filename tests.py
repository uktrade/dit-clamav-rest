import io
import base64
import json
import unittest
from io import BytesIO
from unittest import mock
import requests
import logging

import clamd

import clamav_rest
from clamav_versions import parse_local_version, parse_remote_version
from version import __version__

from flask_testing import LiveServerTestCase

# pylint: disable=anomalous-backslash-in-string
EICAR = b"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

EICAR_TEST_OUTPUTS = (
    "Eicar-Test-Signature",
    "Win.Test.EICAR_HDB-1",
)


def _get_auth_header(username, password):
    creds = base64.b64encode(bytes("{}:{}".format(username, password), "utf-8"))
    return dict(Authorization=b'Basic ' + creds)


def _get_file_data(file_name, data):
    return dict(file=(BytesIO(data), file_name))


def _read_file_data(file_name):
    with open(file_name, "rb") as binary_file:
        data = binary_file.read()
    return dict(file=(BytesIO(data), file_name))


class ClamAVVersionParsing(unittest.TestCase):
    def test_parse_local_version(self):
        expected_version = "12321"
        local_version_text = f"ClamAV 0.100.2/{expected_version}/Fri May 31 07:57:34 2019"
        local_version_number = parse_local_version(local_version_text)
        self.assertEqual(local_version_number, expected_version)

    def test_parse_remote_version(self):
        expected_version = "remote"
        remote_version_text = f"220.101.2:58:{expected_version}:1559294940:1:63:48725:32823"
        remote_version_number = parse_remote_version(remote_version_text)
        self.assertEqual(remote_version_number, expected_version)


class ClamAVirusUpdate(unittest.TestCase):
    def setUp(self):
        clamav_rest.app.config['Testing'] = True
        self.app = clamav_rest.app.test_client()

    @mock.patch("clamav_rest.versions.get_remote_version_number")
    @mock.patch("clamav_rest.versions.get_local_version_number")
    @mock.patch("clamav_rest.cd.ping")
    def test_local_remote_services_are_insync(self, ping, local, remote):
        remote.return_value = "1010101"
        local.return_value = "1010101"
        response = self.app.get("/check_warning")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'1010101')

    @mock.patch("clamav_rest.versions.get_remote_version_number")
    @mock.patch("clamav_rest.versions.get_local_version_number")
    def test_services_out_of_date(self, local, remote):
        remote.return_value = "25466"
        local.return_value = "25465"
        response = self.app.get("/check_warning")
        self.assertEqual(response.status_code, 500)

    @mock.patch("clamav_rest.versions.get_remote_version_number")
    @mock.patch("clamav_rest.versions.get_local_version_number")
    @mock.patch("clamav_rest.cd.ping")
    def test_local_remote_services_are_insync_v2(self, ping, local, remote):
        remote.return_value = "1010101"
        local.return_value = "1010101"
        response = self.app.get("/check_version")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["clamd-actual"], "1010101")
        self.assertEqual(response.json["clamd-required"], "1010101")
        self.assertEqual(response.json["outdated"], False)
        self.assertEqual(response.json["service"], __version__)

    @mock.patch("clamav_rest.versions.get_remote_version_number")
    @mock.patch("clamav_rest.versions.get_local_version_number")
    def test_services_out_of_date_v2(self, local, remote):
        remote.return_value = "25466"
        local.return_value = "25465"
        response = self.app.get("/check_version")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json["clamd-actual"], "25465")
        self.assertEqual(response.json["clamd-required"], "25466")
        self.assertEqual(response.json["outdated"], False)
        self.assertEqual(response.json["service"], __version__)


class ClamAVRESTTestCase(unittest.TestCase):
    def setUp(self):
        clamav_rest.app.config['TESTING'] = True
        self.app = clamav_rest.app.test_client()

    def test_healthcheck(self):
        response = self.app.get("/check")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data, b'Service OK')

    @mock.patch("clamav_rest.cd.ping")
    def test_healthcheck_no_service(self, ping):
        ping.side_effect = clamd.ConnectionError()
        response = self.app.get("/check")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, b'Service Unavailable')

    @mock.patch("clamav_rest.cd.ping")
    def test_healthcheck_unexpected_error(self, ping):
        ping.side_effect = Exception("Oops")
        response = self.app.get("/check")
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.data, b'Service Unavailable')

    def test_scan_endpoint_requires_post(self):
        response = self.app.get("/scan")
        self.assertEqual(response.status_code, 405)

    def test_auth_ok(self):
        response = self.app.post("/scan", headers=_get_auth_header("app1", "letmein"))

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

        self.assertEqual(data["malware"], True)
        self.assertEqual(data["reason"], "Heuristics.Encrypted.Zip")

    def test_eicar(self):
        response = self.app.post("/v2/scan",
                                 headers=_get_auth_header("app1", "letmein"),
                                 content_type='multipart/form-data',
                                 data=_get_file_data(
                                     "eicar.txt", EICAR)
                                 )

        data = json.loads(response.data.decode('utf8'))

        self.assertEqual(data["malware"], True)
        assert data["reason"] in EICAR_TEST_OUTPUTS

    def test_payload_right_size(self):
        # Fake content - 4.9Mb
        content = b"\0" * (clamav_rest.app.config['MAX_CONTENT_LENGTH'] - 10000)
        response = self.app.post("/v2/scan",
                                 headers=_get_auth_header("app1", "letmein"),
                                 content_type='multipart/form-data',
                                 data=_get_file_data(
                                     "4_9Mb.bin", content)
                                 )
        self.assertEqual(response.json["malware"], False)
        self.assertEqual(response.json["reason"], None)
        self.assertEqual(response.status_code, 200)

    def test_payload_too_large(self):
        logger = logging.getLogger('raven.base.Client')
        logger.disabled = True  # Sentry be quiet
        content = b"\0" * clamav_rest.app.config['MAX_CONTENT_LENGTH']
        response = self.app.post("/v2/scan",
                                 headers=_get_auth_header("app1", "letmein"),
                                 content_type='multipart/form-data',
                                 data=_get_file_data(
                                     "5Mb.bin", content)
                                 )
        self.assertEqual(response.data, b"File Too Large")
        self.assertEqual(response.status_code, 413)


class ClamAVRESTV2ScanChunkedTestCase(LiveServerTestCase):
    def create_app(self):
        app = clamav_rest.app
        app.config['TESTING'] = True

        return app

    def setUp(self):
        self.headers = _get_auth_header("app1", "letmein")
        self.headers["Transfer-encoding"] = "chunked"
        self.chunk_url = "http://localhost:5000/v2/scan-chunked"

    @staticmethod
    def _eicar_gen():
        yield b"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
        yield b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    @staticmethod
    def _archive_file():
        with open("client-examples/protected.zip", "rb") as binary_file:
            data = binary_file.read()

        with io.BytesIO(data) as file_data:
            while True:
                # Yield 10 byte chunks
                chunk = file_data.read(10)
                yield chunk
                
                if not chunk:
                    break

    @staticmethod
    def _text_file():
        yield b"NO VIRUS HERE"
        yield b"NO VIRUS HERE"

    def test_encrypted_archive(self):
        response = requests.post(
            self.chunk_url,
            headers=self.headers,
            data=self._archive_file(),
        )

        data = response.json()

        self.assertEqual(data["malware"], True)
        self.assertEqual(data["reason"], "Heuristics.Encrypted.Zip")

    def test_eicar(self):
        response = requests.post(
            self.chunk_url,
            headers=self.headers,
            data=self._eicar_gen(),
        )

        data = response.json()

        self.assertEqual(data["malware"], True)
        assert data["reason"] in EICAR_TEST_OUTPUTS

    def test_clean_data(self):
        response = requests.post(
            self.chunk_url,
            headers=self.headers,
            data=self._text_file(),
        )

        data = response.json()

        self.assertEqual(data["malware"], False)
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()

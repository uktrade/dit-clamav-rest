import json
import logging
import os

from locust import HttpUser, task


# Configuration
REQUESTS_LOGGING = bool(os.environ.get("REQUESTS_LOGGING"))
PERF_USER = os.environ.get("PERF_USER", "app1")
PERF_PWD = os.environ.get("PERF_PWD", "letmein")
USER_FILE = os.environ.get("USER_FILE", "client-examples/5MiB.bin")
CLAMD_RESPONSE_THRESHOLD = float(os.environ.get("CLAMD_RESPONSE_THRESHOLD", 0.01))
CLAMD_VERSION_THRESHOLD = int(os.environ.get("CLAMD_VERSION_THRESHOLD", 3))
AUTH = (PERF_USER, PERF_PWD)


def debug_requests_on():
    """Switches on logging of the requests module."""
    from http.client import HTTPConnection
    HTTPConnection.debuglevel = 1
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    requests_log = logging.getLogger("requests.packages.urllib3")
    requests_log.setLevel(logging.DEBUG)
    requests_log.propagate = True


if REQUESTS_LOGGING:
    debug_requests_on()


logger = logging.getLogger(__name__)


def malware_file_gen():
    """Test malware."""
    yield b"X5O!P%@AP[4\PZX54(P^)7CC)7}$"  # noqa
    yield b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def valid_file_gen():
    """Test file."""
    lorem = b"""
    Lorem ipsum dolor sit amet, consectetur adipiscing elit,
    sed do eiusmod tempor incididunt ut labore et dolore magna
    aliqua. Ut enim ad minim veniam, quis nostrud exercitation
    ullamco laboris nisi ut aliquip ex ea commodo consequat.
    """
    yield lorem
    yield lorem
    yield lorem
    yield lorem


def user_file_gen():
    """A user specified file."""
    try:
        os.stat(USER_FILE)
    except FileNotFoundError as e:
        logger.error(f"{e}")
        return
    with open(USER_FILE, "rb") as f:
        while chunk := f.read(1024):
            yield chunk


class CheckUser(HttpUser):
    host = "http://localhost"

    @task
    def check_service(self):
        """Service healthcheck."""
        self.client.get("/check", name="CHECK")

    @task
    def check_version(self):
        """Service version check.

        This is likely to return HTTP 500 due to outdated clamd virus
        definitions. We consider a fail if version difference is greater
        than CLAMD_VERSION_THRESHOLD.
        """
        with self.client.get("/check_version",
                             name="CHECK_VERSION",
                             catch_response=True) as response:
            response.success()
            if response.status_code == 500:
                actual = int(response.json()["clamd-actual"])
                required = int(response.json()["clamd-required"])
                acceptable = required - CLAMD_VERSION_THRESHOLD
                if actual < acceptable:
                    response.failure(
                        f"Unacceptable clamd version lag: "
                        f"actual: {actual} required: {required} "
                        f"minimum acceptable version: {acceptable}"
                    )


class UnauthorisedUser(HttpUser):
    host = "http://localhost"

    @task
    def check_not_authorised(self):
        """401 Not Authorised check."""
        bad_auth = (PERF_USER, "let-it-go")
        with self.client.post("/v2/scan-chunked",
                              name="UNAUTHORISED",
                              stream=True,
                              auth=bad_auth,
                              headers={"Transfer-encoding": "chunked"},
                              data=valid_file_gen(),  # noqa
                              catch_response=True) as response:
            if response.status_code != 401:
                response.failure(f"Expected 401 got: {response.status_code}")
            else:
                response.success()


class ClamPostUser(HttpUser):
    abstract = True

    @staticmethod
    def parse_response(response):
        """Parse HTTP response data.

        :param (HttpResponse) response: Response to parse.
        :returns (dict): parsed json data or None if parsing failed.
        """
        try:
            return response.json()
        except (ValueError, json.JSONDecodeError) as e:
            logger.error(f"Could not decode response: {e}")
            return None

    @staticmethod
    def check_data(data, threshold=CLAMD_RESPONSE_THRESHOLD):
        """Check response data.

        Check response data returned from CLAMAV Service post.

        :param (dict) data: response data.
        :param (float) threshold: response time threshold.
        :returns (str): An error string if an error encountered,
          None otherwise.
        """
        error = None
        try:
            taken = data["time"]
            if taken > threshold:
                error = f"Response too slow: {taken}"
        except KeyError as e:
            error = f"Missing attribute in response: {e}"
        return error


class ScanUser(ClamPostUser):
    host = "http://localhost"

    @task
    def check_malware_file(self):
        """Malware file check.

        Expected response is something like:
        {
          "malware":true,
          "reason":"Win.Test.EICAR_HDB-1",
          "time":0.006975043099373579
        }
        """
        with self.client.post("/v2/scan-chunked",
                              name="MALWARE",
                              stream=True,
                              auth=AUTH,
                              headers={"Transfer-encoding": "chunked"},
                              data=malware_file_gen(),  # noqa
                              catch_response=True) as response:
            response.success()
            if data := self.parse_response(response):
                if error := self.check_data(data):
                    response.failure(error)
                elif not data.get("malware"):
                    response.failure(f"Invalid response from call: {data}")
            else:
                response.failure("Failed to decode response")

    @task
    def check_clean_file(self):
        """Clean file check.

        Expected response is something like:
        {
          "malware":false,
          "reason":null,
          "time":0.006975043099373579
        }
        """
        with self.client.post("/v2/scan-chunked",
                              name="CLEAN",
                              stream=True,
                              auth=AUTH,
                              headers={"Transfer-encoding": "chunked"},
                              data=valid_file_gen(),  # noqa
                              catch_response=True) as response:
            response.success()
            if data := self.parse_response(response):
                if error := self.check_data(data):
                    response.failure(error)
                elif data.get("malware"):
                    response.failure(f"Invalid response from call: {data}")
            else:
                response.failure("Failed to decode response")

    @task
    def check_user_defined_file(self):
        """User defined file check."""
        with self.client.post("/v2/scan-chunked",
                              name="USER_DEFINED",
                              stream=True,
                              auth=AUTH,
                              headers={"Transfer-encoding": "chunked"},
                              data=user_file_gen(),  # noqa
                              catch_response=True) as response:
            response.success()
            if data := self.parse_response(response):
                if error := self.check_data(data, threshold=1.0):
                    response.failure(error)
                elif data.get("malware"):
                    response.failure(f"Invalid response from call: {data}")
            else:
                response.failure("Failed to decode response")

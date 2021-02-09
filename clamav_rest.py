import io
import os
import logging
import sys
import timeit
import urllib
import uuid
from datetime import datetime

from flask import Flask, request, g, jsonify
from flask_httpauth import HTTPBasicAuth

from clamav_versions import get_remote_version_number, get_local_version_number

import clamd
from passlib.hash import pbkdf2_sha256 as hash
from raven.contrib.flask import Sentry

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

logger = logging.getLogger("CLAMAV-REST")

app = Flask("CLAMAV-REST")
app.config.from_object(os.environ['APP_CONFIG'])
app.config['MAX_CONTENT_LENGTH'] = 9999999

try:
    APPLICATION_USERS = dict([user.split("::") for user in
                              app.config["APPLICATION_USERS"].encode('utf-8').decode('unicode_escape').split("\n") if
                              user])  # noqa
except AttributeError:
    APPLICATION_USERS = {}
    logger.warning("No application users configured.")

sentry = Sentry(app, dsn=app.config.get("SENTRY_DSN", None))

auth = HTTPBasicAuth()

if "CLAMD_SOCKET" in app.config:
    cd = clamd.ClamdUnixSocket(path=app.config["CLAMD_SOCKET"])
else:
    try:
        cd = clamd.ClamdNetworkSocket(
            host=app.config["CLAMD_HOST"], port=app.config["CLAMD_PORT"])
    except BaseException:
        logger.exception("error bootstrapping clamd for network socket")


@auth.verify_password
def verify_pw(username, password):
    app_password = APPLICATION_USERS.get(username, None)

    if not app_password:
        return False

    if hash.verify(password, app_password):
        g.current_user = username
        return True
    else:
        return False


@app.route("/", methods=["GET"])
@app.route("/check", methods=["GET"])
def healthcheck():
    try:
        clamd_response = cd.ping()
        if clamd_response == "PONG":
            return "Service OK"

        logger.error("expected PONG from clamd container")
        return "Service Down", 502

    except clamd.ConnectionError:
        logger.error("clamd.ConnectionError")
        return "Service Unavailable", 502

    except BaseException as e:
        logger.error(e)
        return "Service Unavailable", 500


@app.route("/check_warning", methods=["GET"])
def health_definitions():
    try:

        local_version = get_local_version_number(cd)
        remote_version = get_remote_version_number(
            app.config["CLAMAV_TXT_URI"])

        version_msg = f"local_version: {local_version} remote_version: {remote_version}"

        logger.info(version_msg)

        if remote_version == local_version:
            return remote_version

        return f"Outdated {version_msg}", 500

    except clamd.ConnectionError:
        logger.exception("failed to connect to upstream clamav daemon")
        return "Service Unavailable", 500

    except BaseException:
        logger.exception("Unexpected error when checking av versions.")
        return "Service Unavailable", 500


@app.route("/scan", methods=["POST"])
@auth.login_required
def scan():
    if len(request.files) != 1:
        return "Provide a single file", 400

    _, file_data = list(request.files.items())[0]

    logger.info("Starting scan for {app_user} of {file_name}".format(
        app_user=g.current_user,
        file_name=file_data.filename
    ))

    start_time = timeit.default_timer()
    resp = cd.instream(file_data)
    elapsed = timeit.default_timer() - start_time

    status = "OK" if resp["stream"][0] == "OK" else "NOTOK"

    logger.info("Scan for {app_user} of {file_name} complete. Took: {elapsed}. Status: {status}".format(
        app_user=g.current_user,
        file_name=file_data.filename,
        elapsed=elapsed,
        status=status
    ))

    return status


@app.route("/v2/scan", methods=["POST"])
@auth.login_required
def scan_v2():
    if len(request.files) != 1:
        return "Provide a single file", 400

    _, file_data = list(request.files.items())[0]

    logger.info("Starting scan for {app_user} of {file_name}".format(
        app_user=g.current_user,
        file_name=file_data.filename
    ))

    start_time = timeit.default_timer()
    resp = cd.instream(file_data)
    elapsed = timeit.default_timer() - start_time

    status, reason = resp["stream"]

    response = {
        'malware': False if status == "OK" else True,
        'reason': reason,
        'time': elapsed
    }

    logger.info("Scan v2 for {app_user} of {file_name} complete. Took: {elapsed}. Malware found?: {status}".format(
        app_user=g.current_user,
        file_name=file_data.filename,
        elapsed=elapsed,
        status=response['malware']
    ))

    return jsonify(response)


@app.route("/v2/scan-chunked", methods=["POST"])
@auth.login_required
def scan_chunks():
    try:
        file_name = uuid.uuid4()

        start_time = timeit.default_timer()
        resp = cd.instream(request.stream)
        elapsed = timeit.default_timer() - start_time

        status, reason = resp["stream"]

        response = {
            'malware': False if status == "OK" else True,
            'reason': reason,
            'time': elapsed
        }

        logger.info(
            f"Scan chunk v2 for {g.current_user} of {file_name} complete. Took: {elapsed}. Malware found?: {response['malware']}"
        )

        return jsonify(response)
    except Exception as ex:
        logger.error(f"Exception thrown whilst processing file chunks, ex: '{ex}'")
        return "Exception thrown whilst processing file chunks", 500


if __name__ == "__main__":
    app.run(host=app.config["HOST"], port=app.config["PORT"])

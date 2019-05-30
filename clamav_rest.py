import os
import logging
import sys
import timeit

from flask import Flask, request, g, jsonify
from flask_httpauth import HTTPBasicAuth

from clamav_versions import ClamAVRemoteVersionService, ClamAVLocalVersionService

import clamd
from passlib.hash import pbkdf2_sha256 as hash
from raven.contrib.flask import Sentry

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

logger = logging.getLogger("CLAMAV-REST")

app = Flask("CLAMAV-REST")
app.config.from_object(os.environ['APP_CONFIG'])

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
    except Exception as ex:
        logger.error("error bootstrapping clamd for network socket")
        logger.exception(ex)


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
def healthcheck():
    try:
        clamd_response = cd.ping()
        if clamd_response == "PONG":
            return "Service OK"

        logger.error("expected PONG from clamd container")
        return "Service Down", 502

    except clamd.ConnectionError:
        logger.exception("clamd.ConnectionError")
        return "Service Unavailable", 502
    except Exception as ex:
        logger.exception(ex)
        return "Service Unavailable", 500


@app.route("/health/definitions", methods=["GET"])
def health_definitions():
    try:
        # no point in checking remote if local is down
        local_service = ClamAVLocalVersionService(cd)
        local_version_text = local_service.get_local_version_text()

        if not local_version_text:
            raise Exception("local_version_text is empty - is clamav running")

        local_version = ClamAVLocalVersionService.parse_local_version(
            local_version_text
        )
       
        remote_service = ClamAVRemoteVersionService(
            app.config["CLAMAV_TXT_URI"])
        remote_version = ClamAVRemoteVersionService.parse_remote_version(
            remote_service.get_remote_version_text())

        version_msg = "local_version: %s remote_version: %s" % (
            local_version, remote_version)
        logger.info(version_msg)

        if remote_version == local_version:
            return remote_version

        return "Outdated %s" % version_msg, 500
    except Exception as ex:
        logger.error(ex)
        return "Service Unavailable", 502


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


if __name__ == "__main__":
    app.run(host=app.config["HOST"], port=app.config["PORT"])

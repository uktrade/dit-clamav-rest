import os
import logging
import ecs_logging
import sys
import timeit
import uuid

from flask import Flask, request, g, jsonify
from flask_httpauth import HTTPBasicAuth

import clamd
from passlib.hash import pbkdf2_sha256 as hash
from raven.contrib.flask import Sentry

import clamav_versions as versions
from version import __version__

logger = logging.getLogger("CLAMAV-REST")

logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(ecs_logging.StdlibFormatter())
logger.addHandler(handler)

app = Flask("CLAMAV-REST")
app.config.from_object(os.environ["APP_CONFIG"])

try:
    APPLICATION_USERS = dict(
        [
            user.split("::")
            for user in app.config["APPLICATION_USERS"]
            .encode("utf-8")
            .decode("unicode_escape")
            .split("\n")
            if user
        ]
    )
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
            host=app.config["CLAMD_HOST"], port=app.config["CLAMD_PORT"]
        )
    except BaseException as exc:
        logger.exception(f"error bootstrapping clamd for network socket: {exc}")


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
    """Healthcheck.

    Get service health by pinging clamd daemon.

    :returns: Status string and message. 200 if daemon responds correctly,
      503 (service unavailable) otherwise.
    """
    try:
        clamd_response = cd.ping()
        if clamd_response == "PONG":
            return "Service OK", 200
        logger.error(f"clamd responded abnormally, expected 'PONG'"
                     f" got '{clamd_response}'")
    except clamd.ConnectionError as e:
        logger.error(f"clamd.ConnectionError: {e}")
    except Exception as e:
        logger.error(f"Failed to ping clamd: {e}")
    return "Service Unavailable", 503


@app.route("/check_version", methods=["GET"])
def version():
    """Version.

    Get service version information, including this service's version and
    local/remote clam versions.

    :returns: Json response and status. 200 if version info acquired, 500 otherwise.
      Additionally elicits 500 if there is a local/remote clamd version mismatch.
    """
    status = 200
    response = {"service": __version__}
    try:
        local_version = versions.get_local_version_number(cd)
        remote_version = versions.get_remote_version_number(app.config["CLAMAV_TXT_URI"])
    except versions.VersionError as e:
        logger.error(e)
        response["error"] = f"{e}"
        status = 500
    else:
        response["clamd-actual"] = local_version
        response["clamd-required"] = remote_version
        response["outdated"] = False
        if remote_version != local_version:
            logger.warning(f"clamd outdated - current:{local_version} "
                           f"latest: {remote_version}")
            response["outdated"] = True
            status = 500
    return jsonify(response), status


@app.route("/v2/scan", methods=["POST"])
@auth.login_required
def scan_v2():
    """AV file scan endpoint.

    :returns: Json response of AV scan result. 400 (Bad request) returned if
      not exactly one file provided.
    """
    if len(request.files) != 1:  # noqa
        return "Provide a single file", 400
    _, file_data = list(request.files.items())[0]
    logger.info(f"Starting scan for {g.current_user} of {file_data.filename}")
    start_time = timeit.default_timer()
    try:
        resp = cd.instream(file_data)
        status, reason = resp["stream"]
    except Exception as e:
        msg = f"Exception thrown whilst processing file: '{e}'"
        logger.error(msg)
        return msg, 500
    else:
        elapsed = timeit.default_timer() - start_time
        response = {
            "malware": False if status == "OK" else True,
            "reason": reason,
            "time": elapsed,
        }
        logger.info(
            f"Scan v2 for {g.current_user} of {file_data.filename} complete. "
            f"Took: {elapsed}. Malware found?: {response['malware']}"
        )
        return jsonify(response)


@app.route("/v2/scan-chunked", methods=["POST"])
@auth.login_required
def scan_chunks():
    """Chunked AV file scan endpoint.

    :returns: Json response of AV scan result. 500 (Server Error) returned if
      exception raised while processing chunks.
    """
    file_name = uuid.uuid4()
    start_time = timeit.default_timer()
    try:
        resp = cd.instream(request.stream)
        status, reason = resp["stream"]
    except Exception as e:
        msg = f"Exception thrown whilst processing file chunks: '{e}'"
        logger.error(msg)
        return msg, 500
    else:
        elapsed = timeit.default_timer() - start_time
        response = {
            "malware": False if status == "OK" else True,
            "reason": reason,
            "time": elapsed,
        }
        logger.info(
            f"Scan chunk v2 for {g.current_user} of {file_name} complete. "
            f"Took: {elapsed}. Malware found?: {response['malware']}"
        )
        return jsonify(response)


@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle 413 Request Entity Too Large.

    Rather than just chop the connection, return a 413.
    """
    logger.warning(f"{error}")
    return "File Too Large", 413

@app.after_request
def after_request(response):
    """ Logging after every request. """
    zipkin_headers = ("X-B3-Traceid", "X-B3-Spanid")
    extra_labels = {"X-B3-Traceid": "none", "X-B3-Spanid": "none"}
    for header in request.headers:
        if header[0] in zipkin_headers:
            extra_labels[header[0]] = header[1]
    labels={
        "trace.id": extra_labels["X-B3-Traceid"],
        "span.id": extra_labels["X-B3-Spanid"]
    }
    try:
        labels={**labels,
            "http.request.body.content": request.data,
            "http.request.body.bytes": len(request.data)
        }
    except:
        labels={**labels,
            "http.request.body.content": "none",
            "http.request.body.bytes": 0
        }
    labels={**labels,
        "http.request.method": request.method,
        "http.request.bytes":request.content_length,
        "http.request.mime_type": request.mimetype,
        "http.request.referrer": request.referrer,
        "http.response.status_code": response.status_code,
        "http.response.bytes": response.content_length,
        "http.response.body.content": response.data,
        "http.response.body.bytes": len(response.data),
        "http.response.mime_type": response.mimetype,
        "http.version": request.environ.get('SERVER_PROTOCOL'),
        "source.ip": request.remote_addr,
        "url.path": request.path,
        "url.original":request.url,
        "url.domain": request.host,
        "url.scheme": request.scheme,
        "user_agent.original": request.user_agent
    }
    logger.info(
        "%s %s",
        __name__,
        request.endpoint,
        extra={**labels,**extra_labels}
    )
    return response


#
# DEPRECATED ROUTES
#
@app.route("/check_warning", methods=["GET"])
def health_definitions():
    logger.warning(f"Deprecated endpoint '/check_warning' invoked, use '/check_version' instead")
    try:
        local_version = versions.get_local_version_number(cd)
        remote_version = versions.get_remote_version_number(app.config["CLAMAV_TXT_URI"])
        version_msg = f"local_version: {local_version} remote_version: {remote_version}"
        logger.info(version_msg)
        if remote_version == local_version:
            return remote_version
        return f"Outdated {version_msg}", 500
    except clamd.ConnectionError:
        logger.exception("failed to connect to upstream clamav daemon")
        return "Service Unavailable", 500
    except BaseException:  # noqa
        logger.exception("Unexpected error when checking av versions.")
        return "Service Unavailable", 500


@app.route("/scan", methods=["POST"])
@auth.login_required
def scan():
    logger.warning(f"Deprecated endpoint '/scan' invoked by user '{g.current_user}'"
                   f" use '/v2/scan' or '/v2/scan-chunked' instead")
    if len(request.files) != 1:  # noqa
        return "Provide a single file", 400
    _, file_data = list(request.files.items())[0]
    logger.info(f"Starting scan for {g.current_user} of {file_data.filename}")
    start_time = timeit.default_timer()
    resp = cd.instream(file_data)
    elapsed = timeit.default_timer() - start_time
    status = "OK" if resp["stream"][0] == "OK" else "NOTOK"
    logger.info(
        f"Scan for {g.current_user} of {file_data.filename} complete. "
        f"Took: {elapsed}. Status: {status}"
    )
    return status


if __name__ == "__main__":
    app.run(host=app.config["HOST"], port=app.config["PORT"])

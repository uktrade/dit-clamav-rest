# DIT ClamAV REST interface

This is a python-based REST interface to ClamD inspired by https://github.com/solita/clamav-rest

## Authentication

The `/v2/scan` and `/v2/scan-chunked` endpoints require basic HTTP authentication.
Authentication details are passed in to the service via the `APPLICATION_USERS` 
environment variable which should be in the format:

    "username1::password\nusername2::password\nusername3::password"

Where `password` is a pbkdf2_sha256 hash generated by Python's passlib.
Assuming you have passlib installed, you can generate a password hash like this:

    # python -c "from passlib import hash; print(hash.pbkdf2_sha256.hash('letmein'))"

## Running with docker-compose

    # make up

Check the logs with `docker-compose logs -f` to make sure `clamd` is up before
trying examples below.

> NB: The docker-compose config spins up an NGINX instance
> that listens on port 80. Its configuration specifies a `client_max_body_size`
> of 600Mb which takes precedence over `MAX_CONTENT_LENGTH` env var if
> specified (and `config.DEFAULT_MAX_CONTENT_LENGTH` if not).

## Service health
The following URIs (using a docker compose setup with NGINX proxy listening on
port 80) do not require authentication and perform a basic service health
check including a check that the `clamd` daemon is responding:

    # curl -i localhost
    # curl -i localhost/check

    HTTP/1.1 200 OK
    Server: nginx/1.18.0
    Date: Thu, 25 Mar 2021 22:00:21 GMT
    Content-Type: text/html; charset=utf-8
    Content-Length: 10
    Connection: keep-alive

    Service OK

## Service version info
This URI does not require authentication and returns the service version,
the local `clamd` version what the latest remote version is. If the local
`clamd` version is outdated, it should be updated.

    # curl -i localhost/check_version

    HTTP/1.1 500 INTERNAL SERVER ERROR
    Server: nginx/1.18.0
    Date: Thu, 25 Mar 2021 22:08:23 GMT
    Content-Type: application/json
    Content-Length: 104
    Connection: keep-alive
    
    {
      "clamd-actual": "25480",
      "clamd-required": "26120",
      "outdated": true,
      "service": "1.0.0"
    }

You can verify the reported clamav version using the following:

    # host -t txt current.cvd.clamav.net

    current.cvd.clamav.net descriptive text "0.103.1:59:26120:1616707740:0:63:49191:333"

Where `26120` is the latest version in the above example.

## Scan an example file with user credentials

Here we post a fake 'infected' file called eicar.txt:

    # curl -iF "file=@client-examples/eicar.txt" localhost/v2/scan --user "app1:letmein"

    HTTP/1.1 200 OK
    Server: nginx/1.18.0
    Date: Thu, 25 Mar 2021 22:03:23 GMT
    Content-Type: application/json
    Content-Length: 93
    Connection: keep-alive
    
    {
      "malware": true,
      "reason": "Eicar-Test-Signature",
      "time": 0.0032407999970018864
    }

## Running other client examples

In the client-examples folder you will find a number of examples files you can
use to try out the service.

## HTTP Status Codes
The following HTTP status codes might be returned by the service.

    GET /check

    200 (ok) when service is operational and clamd is responding
    503 (service unavailable) if clamd is not responding

    GET /check_version

    200 (ok) when version info is successfully acquired and clamd is up to date
    500 (error) if version info cannot be successfully acquired or clamd outdated

    POST /v2/scan
    POST /v2/scan-chunked

    400 (bad request) if none, or more than one file is spefified
    401 (not authoirised) if you don't specify credentials or credentials invalid
    413 (too large) if the content sent is too large (default is 1Gb)
    500 unexpected server errors

## Run the unit tests

    make test

## Developing Locally

Pre-requisites

- Docker
- Python3

### Create virtualenv and install pip dependencies

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

### Start the clamd service in a docker container

    docker run -p 3310:3310 -d --name clam ukti/docker-clamav

### Run the unit tests

    APP_CONFIG=config.TestConfig python -m unittest tests.py

### Run the REST api

    APP_CONFIG=config.LocalConfig python clamav_rest.py

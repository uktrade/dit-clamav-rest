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

The usage examples below allow show you how to `curl` the service listening on
`localhost:80` (the nginx proxy set up in `docker-compose.yml`).
[Refer to this section](#using-a-local-instance-with-another-docker-compose-project)
if you want to interact with the service from another locally running docker-compose
project.

### Environment Variable: MIRROR_URL
Note that the [clamav docker container](https://github.com/uktrade/docker-clamav) used by this service requires that the env var [MIRROR_URL](https://github.com/uktrade/docker-clamav/blob/a940abae307d1feb3322462e6e229a96fae257a3/debian/buster/custom-bootstrap.sh#L12) is set, otherwise the following error occurs in the `clamd` service:
```
ERROR: Missing argument for option at /etc/clamav/freshclam.conf
ERROR: Can't open/parse the config file /etc/clamav/freshclam.conf
```
If using this container, ensure the `MIRROR_URL` env var is set in the docker-compose file.

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

Basic usage posting a fake 'infected' file called eicar.txt:

    # curl -iF "file=@client-examples/eicar.txt" http://app1:letmein@localhost/v2/scan

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

A preferable usage scenario is to use the `scan-chunked` endpoint. This
requires a slightly more complicated curl request with additional headers
`Transfer-Encoding` and `Content-Type`. Additionally, --data-binary
ensures the file content is transmitted un-tampered:

    # curl -i http://app1:letmein@localhost/v2/scan-chunked \
      --header 'Content-Type: application/octet-stream' \
      --header 'Transfer-Encoding: chunked' \
      --data-binary '@client-examples/eicar.txt'

    HTTP/1.1 200 OK
    Server: nginx/1.20.1
    Date: Wed, 28 Jul 2021 15:00:11 GMT
    Content-Type: application/json
    Content-Length: 93
    Connection: keep-alive

    {
    "malware": true,
    "reason": "Eicar-Test-Signature",
    "time": 0.0038000690001354087
    }

## Running other client examples

In the client-examples folder you will find a number of examples files you can
use to try out the service.

## HTTP Status Codes
Here are the main HTTP status codes that are returned by the service.

    GET /check

    200 (ok) when service is operational and clamd is responding
    503 (service unavailable) if clamd is not responding

    GET /check_version

    200 (ok) when version info is successfully acquired and clamd is up to date
    500 (error) if version info cannot be successfully acquired or clamd outdated

    POST /v2/scan
    POST /v2/scan-chunked

    200 (ok) if virus check completes and no virus found 
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

### Using a local instance with another docker-compose project

You may want to interact with this service from a client in another locally
running compose project.

#### In the other project:
In the other project's `docker-compose.yml` identify the services you want
to integrate with ClamAV and (if not already specified) add a proxy network
e.g. `proxynet`. At the bottom of the compose file (if not already specified)
add an external network e.g. `other_project_network`. When the
`other_project` services start, they will join the network called
`other_project_network` (if it doesn't exist, it will be created). For example:

    version: "3"
    services:
      client_of_clam:
        ...
        networks:
          - proxynet

    ...
    networks:
      proxynet:
        name: other_project_network

#### In this project:
Append the following to the bottom of this project's `docker-compose.yml`:

    networks:
      default:
        external: true
        name: other_project_network

Make sure both projects have been restarted with the new configurations.
You can establish your configuration has worked in the following ways:

#### Use docker network inspect:

    # docker network inspect other_project_network

    [
        {
            "Name": "other_project_network",
            "Id": "1612f2...be91d6424eab420a",
            ...
            "Containers": {
                "db897938...79a11f6c": {
                    "Name": "client_of_clam_1",
                    ...
                },
                "f355238d...0d69c6af": {
                    "Name": "dit-clamav-rest_clamd_1",
                    ...
                },
                ...
   ]

Here you can see that the `dit-clamav-rest_clamd_1` service is on the
`other_project_network` along with `client_of_clam_1`.

#### Use ping:

Additionally, hop onto the container in _the other project_ and ping the
ClamAV proxy:

    # docker-compose exec client_of_clam bash

    root@2f1e42ea7911:/app# ping nginx

    PING nginx (172.24.0.14) 56(84) bytes of data.
    64 bytes from dit-clamav-rest_nginx_1.other_project_network (172.24.0.14):...
    64 bytes from dit-clamav-rest_nginx_1.other_project_network (172.24.0.14):...
    64 bytes from dit-clamav-rest_nginx_1.other_project_network (172.24.0.14):...

Here you can see that the `nginx` service is responding to the
`client_of_clam` service over ICMP.
test test

# DIT ClamAV REST interface

This is a python-based REST interface to ClamD inspired by https://github.com/solita/clamav-rest

### Authentication

The /scan endpoint requires basic HTTP authentication.  Authentication details are passed in via the APPLICATION_USERS environment variable which should be in the format:

    "username1::password\nusername2::password\nusername3::password"

Where `password` is a pbkdf2_sha256 hash generated by Python's passlib.  Assuming you have passlib installed, you can generate a password hash like this:

    python -c "from passlib import hash; print(hash.pbkdf2_sha256.hash('password'))"

## Developing Locally

Pre-requisites

- Docker
- Python3

#### Create virtualenv and install pip dependencies
    
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

#### Start the clamd service in a docker container

    docker run -p 3310:3310 -d --name clam ukti/docker-clamav

#### Run the unit tests

    APP_CONFIG=config.LocalConfig python -m unittest tests.py

#### Run the REST api

    APP_CONFIG=config.LocalConfig python clamav_rest.py

#### Health checks

Basic Service Check

    curl -X GET localhost:8090


Virus definitions check
Check [Authentication](###Authentication) for `username` and `password` details


    curl localhost:8090/health/definitions --user username:password


returns

    200 when virus definitions are up to date

    401 if you didn't send credentials or credentials invalid

    502 when definitions are out of date
        response contains the versions

    500 unexpected server errors


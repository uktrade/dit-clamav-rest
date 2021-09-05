# Performance Tests
The directory contains the service's performance tests implemented using 
[Locust](https://locust.io/), a [well maintained and mature](https://github.com/locustio/locust)
open source project, with excellent [documentation](https://docs.locust.io/). 

## Getting started
For test development and demonstration purposes you can run the 
performance tests and see the results locally. Make sure you have an 
environment built from `requirements.txt` and that an instance of the
`dit-clamav-rest` is running, ideally using the `make up` command as described
in this project's [README](../README.md).

```commandline
locust -f perf/locustfile.py
[2021-09-05 14:36:02,807] MacBook-Pro.local/INFO/locust.main: Starting web interface at http://0.0.0.0:8089 (accepting connections from all network interfaces)
[2021-09-05 14:36:02,814] MacBook-Pro.local/INFO/locust.main: Starting Locust 2.1.0
```

This launches a web service; navigate a browser to `http://localhost:8089`:

![Alt text](landing.png?raw=true "Locust Home Page")

Enter `3` for the number of users and click `Start Sawrming` (setting the 
number of users appropriately ensures at least one user of each type is 
spawned in the swarm). The test run will start, and you will see the 
statistics page start to populate with test results: 

![Alt text](stats.png?raw=true "Locust Statistics Page")

## Test organisation
The performance tests in [locust.py](/perf/locustfile.py) define a set of
"user" classes (`CheckUser`, `UnauthorisedUser`, `ScanUser`) and the type of
service interaction each will perform, defined each user's `@task` methods. 

For example the `CheckUser` will hit the `/check` and `check_version` service
endpoints using the `CheckUser.check_service` and `CheckUsercheck_version` tasks 
respectively. Each task is named, for example: `CHECK`, `CHECK_VERSION`, 
`MALWARE` which can bee seen in the `Name` column on the Statistics page.

The number of requests, failures, response times, requests per second and more
are listed on the statistics page. Explore the other pages for test run 
charts, failures, exceptions raised and data download.

![Alt text](charts.png?raw=true "Locust Charts Page")

## Test settings
Test behaviour can be controlled using various
[locust configuration options](https://docs.locust.io/en/stable/configuration.html)
as well as this repository's test specific configuration environment variables
listed below.

### `PERF_USER`
type:`str` default: `app1`

Coerces the value of the `AUTH` global used in the tests. The default value
works out of the box but must be set appropriately for testing `dit-clamav-rest`
running in the PaaS.

### `PERF_PWD`
type:`str` default: `letmein`

Coerces the value of the `AUTH` global used in the tests. The default value
works out of the box but must be set appropriately for testing `dit-clamav-rest`
running in the PaaS.

### `USER_FILE`
type:`path` default: `client-examples/5MiB.bin`

Uses the specified file in the `check_user_defined_file` task.

### `CLAMD_RESPONSE_THRESHOLD`
type:`float` default: `0.01`

In its response the `dit-clamav-rest` service provides the time it took the
`clamd` daemon to provide its response. Use this setting to specify the
threshold at which a response time is so slow and should be considered a
failure. Analysis of the test run statistics can then later determine if the
overall number of failures have deteriorated/are acceptable.

### `CLAMD_VERSION_THRESHOLD`
type:`int` default: `3`

In its response to the `/check_version` request, the `dit-clamav-rest` service
specifies the actual and required clam version. The `check_version` task
examines the reported versions. Use this setting to specify the version lag
threshold at which the reported version should be considered a failure.

While this test sounds "not very performance related" it is an important
validation of the service, due to the way it's deployed. At start up the
service will likely have an old `cvd` database that's baked into the 
container image at build time. `freshclam` will refresh the on-container
database but this takes a while from a cold start. This manifests itself as
a flurry of initial failures which then fade when the `cvd` is updated. This 
test helps ascertain that service instances can acceptably stabilise thier
virus definition databases.

### `REQUESTS_LOGGING`
type:`boolean` default: `false`

Set to `true` to surface `requests` package logging in the logged output.
Verbose, but useful for debugging tests.

## Locust settings
To Important `locust` settings are:

### `LOCUST_HOST`
type:`str` default: `http://localhost`

command line: `-H <hostname>`, `--host <hostname>`

## Headless execution
Ideally the performance tests should be executed in CI, perhaps as a pre-release
step or periodically to capture any degradation of a deployed AV service's
performance, rather than running the tests locally on an ad-hoc basis using
the web client. 

Given valid [test settings](#test-settings) (in particular `PERF_USER` and
`PERF_PWD`), an example of a simple headless invocation is as follows: 

```commandline
locust -f perf/locust.py --headless -u 100 -r 10 --run-time 1h30m --stop-timeout 60
```

- `-f` our locust file
- `-u` number of users to spawn
- `-r` number of users to start per second

Refer to the [locust documentation](https://docs.locust.io/en/stable/running-without-web-ui.html)
for details on headless execution.
Additionally, deploying using a [locust docker image](https://docs.locust.io/en/stable/running-locust-docker.html)
is an option that may be considered.

## Distributed load generation
It's possible that a single machine won’t be enough to simulate the number of 
users, and the requests per second required for industrial scale load testing 
Refer to the [locust documentation](https://docs.locust.io/en/stable/running-locust-distributed.html) 
to understand how to run these performance tests distributed across multiple 
machines.

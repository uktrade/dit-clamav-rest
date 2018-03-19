#!/usr/bin/env bash

curl -F "file=@eicar.txt" http://app1:letmein@localhost/v2/scan

# password protected files are also blocked when ArchiveBlockEncrypted=true in clamd.conf
# this will be default behaviour for the DIT AV-API going forward.
curl -F "file=@protected.zip" http://app1:letmein@localhost/v2/scan

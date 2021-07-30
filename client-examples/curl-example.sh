#!/usr/bin/env bash

curl -F "file=@eicar.txt" http://app1:letmein@localhost/v2/scan

# password protected files are also blocked when ArchiveBlockEncrypted=true in clamd.conf
# this will be default behaviour for the DIT AV-API going forward.
curl -F "file=@protected.zip" http://app1:letmein@localhost/v2/scan

# Example for scan-chunked endpoint that requires additional headers;
# Transfer-Encoding and Content-Type. Additionally --data-binary
# ensures the file content is transmitted un-tampered.
curl http://app1:letmein@localhost/v2/scan-chunked \
  --request 'POST' \
  --header 'Content-Type: application/octet-stream' \
  --header 'Transfer-Encoding: chunked' \
  --data-binary '@client-examples/eicar.txt'

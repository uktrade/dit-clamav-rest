# Requires python-requests: pip install requests

# Streaming large files: https://toolbelt.readthedocs.io/en/latest/

import requests


auth = ("app1", "letmein")
files = {"file": open("eicar.txt", "rb")}

# Standard V1 scan
response = requests.post("http://localhost/scan", auth=auth, files=files)

print("Standard V1 request response:")
print(response.text)

# Standard V2 scan
response = requests.post("http://localhost/v2/scan", auth=auth, files=files)

print("Standard V2 request response:")
print(response.text)

# Chunked scan
def _eicar_gen():
    yield b"X5O!P%@AP[4\PZX54(P^)7CC)7}$"
    yield b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

response = requests.post(
    "http://localhost/v2/scan-chunked",
    auth=auth,
    headers={
    	"Transfer-encoding": "chunked"
    },
    data=_eicar_gen(),
)

print("Chunked request response:")
print(response.text)

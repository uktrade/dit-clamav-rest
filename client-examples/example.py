# Requires python-requests: pip install requests

# Streaming large files: https://toolbelt.readthedocs.io/en/latest/

import requests

auth = ("app1", "letmein")
files = {"file": open("eicar.txt", "rb")}

response = requests.post("http://localhost:8090/scan", auth=auth, files=files)

print(response.text)

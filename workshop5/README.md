# Who is accessing my file?

Assume we have a sensitive file `sensitive.key` that we want to protect.
Let's understand how to track every process that accessing it, and how to prevent them from doing so!


## Prerequisites
- Any linux machine (ubuntu, debian, etc.)
- BCC - [installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md)
  - Installing BCC might not work as expected. So we are collecting good links for possible errors:
    - https://stackoverflow.com/questions/61978175/how-to-compile-bcc-on-ubuntu-20-04
    - https://github.com/iovisor/bcc/issues/3601
- go version 1.16+ - [installation guide](https://go.dev/doc/install)

You can install those requirements on your local machine, or you can use a predefined docker!
Note: The docker was tested on ubuntu 20.04 with kernel `5.13.0-28-generic`.
If you do have troubles with BCC from the docker, please install BCC and goland on your machine and don't use the docker.

## Running TLS server
```bash
cd tls_server
python3 echo_server.py <port>
```

## Running tls sniffer
```bash
cd cmd/sniffer
sudo go run main.go ./tls_capture.c --pid <server pid>
```

Now try to run
```python3
import requests

body = {"this": "is", "a": ["tls", "test"]}
resp = requests.post("https://127.0.0.1:<port>/example", json=body, verify=False)
```

And the output of the watcher will be:
```bash
****************
Got ingress traffic {pid: 52069, time: 2022-02-28 14:29:00.255375567 +0200 IST, buffer: POST /example HTTP/1.1
Host: 127.0.0.1:9011
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 36
Content-Type: application/json

}
****************
****************
Got ingress traffic {pid: 52069, time: 2022-02-28 14:29:00.2556408 +0200 IST, buffer: {"this": "is", "a": ["tls", "test"]}}
****************
****************
Got egress traffic {pid: 52069, time: 2022-02-28 14:29:00.255843954 +0200 IST, buffer: HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.8.10
Date: Mon, 28 Feb 2022 12:29:00 GMT
Content-type: application/json
Content-length: 36

}
****************
****************
Got egress traffic {pid: 52069, time: 2022-02-28 14:29:00.255894505 +0200 IST, buffer: {"this": "is", "a": ["tls", "test"]}}
****************

```

# The details

We are hooking the `SSL_read`, `SSL_read_ex`, `SSL_write`, and `SSL_write_ex` method from `openssl`.

Those functions hold the decrypted data before encrypting and writing it to a file descriptor, and after reading and decrypting.

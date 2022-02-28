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

## Creating the secret file
```bash
echo "TOP SECRET" > sensitive.key
```

## Running our watcher
```bash
cd cmd/watcher
sudo go run main.go ./watcher.c --level 1
```

Now try to run
```bash
cat sensitive.key
```

And the output of the watcher will be:
```bash
****************
Got open event for {path: sensitive.key, return code: 3, pid: 13630, time: 2022-02-28 10:38:08.291390023 +0200 IST}
****************
```

## Denying access

Open a python shell and run
```python
import os

os.getpid()
```

Assume the result is `2222`

Now, open another python shell.

run the watcher in denied mode

```bash
cd cmd/watcher
sudo go run main.go ./watcher.c --level 2 --level2-pid 2222
```

If you try to access `sensitive.key` file from the first python shell, it'll work for you without any problem.
But if you try to access it from the second shell, you'll get permission denied!


# The details

We are hooking the `openat` syscall, which is responsible for opening files in the system, and it is widely used in the system.

In the first level, we are sending an event from the kernel to the user mode if the `openat` syscall is being called on path that ends with `sensitive.key`.
We are in audit mode.

In the second level, we are changing the return code of the syscall, if the path ends with `sensitive.key` and the process id accessing the file
is not whitelisted.

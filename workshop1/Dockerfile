FROM golang:1.16-bullseye as builder

RUN apt-get update

# According to https://packages.debian.org/source/sid/bpfcc,
# BCC build dependencies:
RUN apt-get install -y arping bison clang-format cmake dh-python \
  dpkg-dev pkg-kde-tools ethtool flex inetutils-ping iperf \
  libbpf-dev libclang-dev libclang-cpp-dev libedit-dev libelf-dev \
  libfl-dev libzip-dev linux-libc-dev llvm-dev libluajit-5.1-dev \
  luajit python3-netaddr python3-pyroute2 python3-distutils python3 git

# Install and compile BCC
RUN git clone https://github.com/iovisor/bcc.git
RUN mkdir bcc/build
WORKDIR bcc/build
RUN cmake ..
RUN make
RUN make install

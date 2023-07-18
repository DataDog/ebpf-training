#!/bin/bash

## Validating kernel config parameters
grep -Ew 'CONFIG_BPF|CONFIG_BPF_SYSCALL|CONFIG_NET_CLS_BPF|CONFIG_NET_ACT_BPF|CONFIG_BPF_JIT|CONFIG_HAVE_EBPF_JIT|CONFIG_BPF_EVENTS|CONFIG_IKHEADERS|CONFIG_NET_SCH_SFQ|CONFIG_NET_ACT_POLICE|CONFIG_NET_ACT_GACT|CONFIG_DUMMY|CONFIG_VXLAN'  /boot/config-5.15.0-1041-azure

echo "Started installing the required packages..."

sudo apt-get update
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
# sudo opensnoop-bpfcc

# echo "export PATH=$PATH:/usr/local/go/bin" >> /etc/profile
wget https://go.dev/dl/go1.20.6.linux-amd64.tar.gz
sudo su
rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.6.linux-amd64.tar.gz

export PATH=$PATH:/usr/local/go/bin
/usr/local/go/bin/go version

export CGO_ENABLED=1
sudo apt install -y zip bison build-essential cmake flex git libedit-dev \
  libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-setuptools \
  liblzma-dev arping netperf iperf

sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 4052245BD4284CDD
echo "deb https://repo.iovisor.org/apt/$(lsb_release -cs) $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/iovisor.list
sudo apt-get update
sudo apt-get install bcc-tools libbcc-examples linux-headers-$(uname -r)

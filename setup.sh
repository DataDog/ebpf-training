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
go version


#!/bin/bash

sudo apt install -y python3-pip
sudo pip3 install dnslib
sudo python3 python_ebpf/final_code_eBPF_dns.py

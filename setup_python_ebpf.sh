#!/bin/bash

wget https://gist.githubusercontent.com/oghie/b4e3accf1f87afcb939f884723e2b462/raw/fe60e6b66135640ea39c878589fb092b6eb838a1/final_code_eBPF_dns.py
sudo apt install python3-pip
sudo pip3 install dnslib
sudo python3 final_code_eBPF_dns.py
